#requires -Version 5.1
<#
.SYNOPSIS
    Discovers subdomains using crt.sh and crt.name, then enumerates selected services.

.DESCRIPTION
    Imports apex domains from a CSV column named "Asset Name".

    For every apex domain, the script:
      1. Queries the crt.sh JSON endpoint.
      2. Parses common_name and multiline name_value fields.
      3. Queries the crt.name newline-delimited search endpoint independently.
      4. Normalizes, scopes, deduplicates, and merges names from both providers.
      5. Preserves wildcard-certificate evidence without treating a wildcard as a
         concrete discovered hostname.
      6. Attempts TCP connections to ports 80, 443, 22, and 3389.
      7. Retrieves HTTP and HTTPS titles when the corresponding TCP port is open.
      8. Exports structured CSV evidence even if either discovery provider fails.

    Certificate-transparency and third-party discovery results are leads. A returned
    hostname does not prove that it currently resolves, is reachable, or remains
    controlled by the organization associated with the apex domain.

.PARAMETER CsvPath
    CSV path. The CSV must contain a column named "Asset Name".

.PARAMETER OutputPath
    Optional results CSV path. The default is a timestamped file in the current
    directory.

.PARAMETER CrtShTimeoutSec
    Timeout for each crt.sh request. Default: 45 seconds.

.PARAMETER CrtNameTimeoutSec
    Timeout for each crt.name request. Default: 30 seconds.

.PARAMETER MaxAttempts
    Maximum request attempts for each discovery provider. Default: 3.

.PARAMETER TcpTimeoutMs
    Timeout for each TCP connection attempt. Default: 3000 milliseconds.

.PARAMETER HttpTimeoutSec
    Timeout for HTTP title retrieval. Default: 10 seconds.

.EXAMPLE
    .\crt_enum.ps1 -CsvPath .\t.csv

.EXAMPLE
    .\crt_enum.ps1 -CsvPath .\domains.csv -OutputPath .\crt_results.csv

.NOTES
    Version: 3.0.0
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateRange(5, 300)]
    [int]$CrtShTimeoutSec = 45,

    [Parameter()]
    [ValidateRange(5, 300)]
    [int]$CrtNameTimeoutSec = 30,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$MaxAttempts = 3,

    [Parameter()]
    [ValidateRange(100, 60000)]
    [int]$TcpTimeoutMs = 3000,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$HttpTimeoutSec = 10
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptVersion = '3.0.0'
$BrowserUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0'
$Results = New-Object 'System.Collections.Generic.List[object]'

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path (Get-Location) -ChildPath (
        'crt_results_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    )
}

function Write-Status {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'DEBUG')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $color = switch ($Level) {
        'INFO'    { 'Cyan' }
        'SUCCESS' { 'Green' }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red' }
        'DEBUG'   { 'DarkGray' }
    }

    Write-Host ('[{0}] {1}' -f $Level, $Message) -ForegroundColor $color
}

function Get-OptionalPropertyValue {
    param (
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [object]$DefaultValue = $null
    )

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $DefaultValue
    }

    return $property.Value
}

function New-WebRequestParameters {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSec,

        [Parameter(Mandatory = $true)]
        [string]$Accept
    )

    $parameters = @{
        Uri                = $Uri
        Method             = 'Get'
        TimeoutSec         = $TimeoutSec
        ErrorAction        = 'Stop'
        MaximumRedirection = 5
        Headers            = @{
            Accept          = $Accept
            'Cache-Control' = 'no-cache'
            Pragma          = 'no-cache'
            'User-Agent'    = $BrowserUserAgent
        }
    }

    if ($PSVersionTable.PSVersion.Major -le 5) {
        $parameters['UseBasicParsing'] = $true
    }

    return $parameters
}

function Normalize-ApexDomain {
    param ([Parameter(Mandatory = $true)][string]$Value)

    $candidate = $Value.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($candidate)) { return $null }

    if ($candidate -match '^[a-z][a-z0-9+.-]*://') {
        try { $candidate = ([uri]$candidate).DnsSafeHost.ToLowerInvariant() }
        catch { return $null }
    }

    $candidate = $candidate.TrimEnd('.')
    if ($candidate.StartsWith('*.')) { $candidate = $candidate.Substring(2) }

    if ($candidate.Length -gt 253 -or $candidate.IndexOf('.') -lt 1) {
        return $null
    }

    if ([uri]::CheckHostName($candidate) -ne [System.UriHostNameType]::Dns) {
        return $null
    }

    return $candidate
}

function ConvertTo-NormalizedDnsName {
    param ([Parameter(Mandatory = $true)][string]$Value)

    $candidate = $Value.Trim().ToLowerInvariant().TrimEnd('.')
    $isWildcard = $candidate.StartsWith('*.')

    if ($isWildcard) {
        $candidate = $candidate.Substring(2)
    }

    if ([string]::IsNullOrWhiteSpace($candidate) -or $candidate.Length -gt 253) {
        return $null
    }

    if ([uri]::CheckHostName($candidate) -ne [System.UriHostNameType]::Dns) {
        return $null
    }

    return [pscustomobject]@{
        Name       = $candidate
        IsWildcard = $isWildcard
    }
}

function Test-DomainScope {
    param (
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$ApexDomain
    )

    return (
        $Candidate.Equals($ApexDomain, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Candidate.EndsWith('.' + $ApexDomain, [System.StringComparison]::OrdinalIgnoreCase)
    )
}

function Invoke-CrtShSearch {
    param ([Parameter(Mandatory = $true)][string]$Domain)

    $query = '%.' + $Domain
    $url = 'https://crt.sh/?q={0}&output=json' -f [uri]::EscapeDataString($query)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Status INFO ('crt.sh attempt {0}/{1}: {2}' -f $attempt, $MaxAttempts, $url)

        try {
            $requestParameters = New-WebRequestParameters -Uri $url -TimeoutSec $CrtShTimeoutSec -Accept 'application/json, text/plain, */*'
            $response = Invoke-WebRequest @requestParameters
            $content = [string]$response.Content

            if ([string]::IsNullOrWhiteSpace($content)) {
                throw 'crt.sh returned an empty response.'
            }

            $entries = @($content | ConvertFrom-Json -ErrorAction Stop)
            return [pscustomobject]@{
                Succeeded = $true
                Url       = $url
                Entries   = $entries
                Error     = ''
            }
        }
        catch {
            Write-Status ERROR ('crt.sh attempt {0} failed: {1}' -f $attempt, $_.Exception.Message)
            if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds ([Math]::Min($attempt * 2, 10)) }
            $lastError = $_.Exception.Message
        }
    }

    return [pscustomobject]@{
        Succeeded = $false
        Url       = $url
        Entries   = @()
        Error     = $lastError
    }
}

function Invoke-CrtNameSearch {
    param ([Parameter(Mandatory = $true)][string]$Domain)

    $url = 'https://crt.name/v1/search?apex={0}' -f [uri]::EscapeDataString($Domain)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Status INFO ('crt.name attempt {0}/{1}: {2}' -f $attempt, $MaxAttempts, $url)

        try {
            $requestParameters = New-WebRequestParameters -Uri $url -TimeoutSec $CrtNameTimeoutSec -Accept 'text/plain, */*'
            $response = Invoke-WebRequest @requestParameters
            $content = [string]$response.Content

            if ([string]::IsNullOrWhiteSpace($content)) {
                throw 'crt.name returned an empty response.'
            }

            $lines = @($content -split '[\r\n]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            return [pscustomobject]@{
                Succeeded = $true
                Url       = $url
                Lines     = $lines
                Error     = ''
            }
        }
        catch {
            Write-Status ERROR ('crt.name attempt {0} failed: {1}' -f $attempt, $_.Exception.Message)
            if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds ([Math]::Min($attempt * 2, 10)) }
            $lastError = $_.Exception.Message
        }
    }

    return [pscustomobject]@{
        Succeeded = $false
        Url       = $url
        Lines     = @()
        Error     = $lastError
    }
}

function Get-CrtShNames {
    param (
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries,
        [Parameter(Mandatory = $true)][string]$ApexDomain
    )

    $concrete = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $wildcardEvidence = $false

    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }

        foreach ($propertyName in @('name_value', 'common_name')) {
            $value = Get-OptionalPropertyValue -InputObject $entry -PropertyName $propertyName
            if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }

            foreach ($rawName in ([string]$value -split '[\r\n]+')) {
                $normalized = ConvertTo-NormalizedDnsName -Value $rawName
                if ($null -eq $normalized) { continue }
                if (-not (Test-DomainScope -Candidate $normalized.Name -ApexDomain $ApexDomain)) { continue }

                if ($normalized.IsWildcard) {
                    $wildcardEvidence = $true
                    continue
                }

                [void]$concrete.Add($normalized.Name)
            }
        }
    }

    return [pscustomobject]@{
        ConcreteNames    = @($concrete | Sort-Object)
        WildcardEvidence = $wildcardEvidence
    }
}

function Get-CrtNameNames {
    param (
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$ApexDomain
    )

    $concrete = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($line in @($Lines)) {
        $normalized = ConvertTo-NormalizedDnsName -Value $line
        if ($null -eq $normalized -or $normalized.IsWildcard) { continue }
        if (Test-DomainScope -Candidate $normalized.Name -ApexDomain $ApexDomain) {
            [void]$concrete.Add($normalized.Name)
        }
    }

    return @($concrete | Sort-Object)
}

function Test-TcpPort {
    param (
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port
    )

    $client = $null
    $waitHandle = $null

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $client.BeginConnect($Target, $Port, $null, $null)
        $waitHandle = $asyncResult.AsyncWaitHandle

        if (-not $waitHandle.WaitOne($TcpTimeoutMs, $false)) {
            return [pscustomobject]@{ Reachable = $false; State = 'NotDetected'; Detail = 'Connection attempt timed out.' }
        }

        $client.EndConnect($asyncResult)
        return [pscustomobject]@{ Reachable = $true; State = 'Open'; Detail = '' }
    }
    catch {
        return [pscustomobject]@{ Reachable = $false; State = 'NotDetected'; Detail = $_.Exception.Message }
    }
    finally {
        if ($null -ne $waitHandle) { $waitHandle.Close() }
        if ($null -ne $client) { $client.Close(); $client.Dispose() }
    }
}

function Get-ResponseFinalUrl {
    param (
        [Parameter(Mandatory = $true)][object]$Response,
        [Parameter(Mandatory = $true)][string]$DefaultUrl
    )

    $baseResponse = Get-OptionalPropertyValue -InputObject $Response -PropertyName 'BaseResponse'
    if ($null -eq $baseResponse) { return $DefaultUrl }

    foreach ($propertyName in @('RequestMessage', 'ResponseUri')) {
        $propertyValue = Get-OptionalPropertyValue -InputObject $baseResponse -PropertyName $propertyName
        if ($null -eq $propertyValue) { continue }

        if ($propertyName -eq 'RequestMessage') {
            $requestUri = Get-OptionalPropertyValue -InputObject $propertyValue -PropertyName 'RequestUri'
            if ($null -ne $requestUri) { return [string]$requestUri }
        }
        elseif ($null -ne $propertyValue) {
            return [string]$propertyValue
        }
    }

    return $DefaultUrl
}

function Get-HttpTitle {
    param (
        [Parameter(Mandatory = $true)][ValidateSet('http', 'https')][string]$Scheme,
        [Parameter(Mandatory = $true)][string]$HostName
    )

    $url = '{0}://{1}/' -f $Scheme, $HostName
    Write-Status DEBUG ('Fetching {0}' -f $url)

    try {
        $requestParameters = New-WebRequestParameters -Uri $url -TimeoutSec $HttpTimeoutSec -Accept 'text/html,application/xhtml+xml,*/*'
        $response = Invoke-WebRequest @requestParameters
        $content = [string]$response.Content
        $title = ''

        if ($content -match '(?is)<title\b[^>]*>(.*?)</title>') {
            $title = [System.Net.WebUtility]::HtmlDecode($matches[1])
            $title = ($title -replace '\s+', ' ').Trim()
        }

        return [pscustomobject]@{
            RequestedUrl = $url
            FinalUrl     = Get-ResponseFinalUrl -Response $response -DefaultUrl $url
            StatusCode   = Get-OptionalPropertyValue -InputObject $response -PropertyName 'StatusCode'
            Title        = $title
            Error        = ''
        }
    }
    catch {
        $statusCode = $null
        $exceptionResponse = Get-OptionalPropertyValue -InputObject $_.Exception -PropertyName 'Response'
        if ($null -ne $exceptionResponse) {
            $statusCode = Get-OptionalPropertyValue -InputObject $exceptionResponse -PropertyName 'StatusCode'
        }

        return [pscustomobject]@{
            RequestedUrl = $url
            FinalUrl     = ''
            StatusCode   = $statusCode
            Title        = ''
            Error        = $_.Exception.Message
        }
    }
}

function New-EmptyHttpResult {
    return [pscustomobject]@{
        RequestedUrl = ''; FinalUrl = ''; StatusCode = $null; Title = ''; Error = ''
    }
}

Write-Host '========== START ==========' -ForegroundColor Cyan
Write-Status INFO ('Script version: {0}' -f $ScriptVersion)
Write-Status INFO ('Input CSV: {0}' -f $CsvPath)
Write-Status INFO ('Output CSV: {0}' -f $OutputPath)

try {
    if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
        throw ('CSV file not found: {0}' -f $CsvPath)
    }

    $importedRows = @(Import-Csv -LiteralPath $CsvPath)
    if ($importedRows.Count -eq 0) { throw 'The CSV contains no data rows.' }

    $columns = @($importedRows[0].PSObject.Properties.Name)
    if ($columns -notcontains 'Asset Name') {
        throw ('The CSV must contain an "Asset Name" column. Found: {0}' -f ($columns -join ', '))
    }

    $rows = @($importedRows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.'Asset Name') })
    Write-Status INFO ('CSV data rows: {0}' -f $importedRows.Count)
    Write-Status INFO ('Nonblank assets: {0}' -f $rows.Count)

    $sourceDomains = @(
        @(
            foreach ($row in $rows) {
                $domain = Normalize-ApexDomain -Value ([string]$row.'Asset Name')
                if ($null -ne $domain) { $domain }
                else { Write-Status WARNING ('Skipping invalid asset: {0}' -f [string]$row.'Asset Name') }
            }
        ) | Sort-Object -Unique
    )

    if ($sourceDomains.Count -eq 0) { throw 'No valid apex domains were found.' }

    $domainNumber = 0
    foreach ($domain in $sourceDomains) {
        $domainNumber++
        Write-Host ''
        Write-Host '==============================' -ForegroundColor Cyan
        Write-Status INFO ('Processing domain {0}/{1}: {2}' -f $domainNumber, $sourceDomains.Count, $domain)

        # Both providers are always queried. crt.name is not merely a failure fallback.
        $crtShResult = Invoke-CrtShSearch -Domain $domain
        $crtNameResult = Invoke-CrtNameSearch -Domain $domain

        $crtShParsed = Get-CrtShNames -Entries @($crtShResult.Entries) -ApexDomain $domain
        $crtNameNames = @(Get-CrtNameNames -Lines @($crtNameResult.Lines) -ApexDomain $domain)

        Write-Status INFO ('crt.sh certificate entries: {0}' -f @($crtShResult.Entries).Count)
        Write-Status INFO ('crt.sh concrete names: {0}' -f @($crtShParsed.ConcreteNames).Count)
        Write-Status INFO ('crt.sh wildcard evidence: {0}' -f $crtShParsed.WildcardEvidence)
        Write-Status INFO ('crt.name concrete names: {0}' -f $crtNameNames.Count)

        $nameProviders = @{}
        foreach ($name in @($crtShParsed.ConcreteNames)) {
            if (-not $nameProviders.ContainsKey($name)) { $nameProviders[$name] = New-Object 'System.Collections.Generic.List[string]' }
            if (-not $nameProviders[$name].Contains('crt.sh')) { $nameProviders[$name].Add('crt.sh') }
        }
        foreach ($name in $crtNameNames) {
            if (-not $nameProviders.ContainsKey($name)) { $nameProviders[$name] = New-Object 'System.Collections.Generic.List[string]' }
            if (-not $nameProviders[$name].Contains('crt.name')) { $nameProviders[$name].Add('crt.name') }
        }
        if (-not $nameProviders.ContainsKey($domain)) {
            $nameProviders[$domain] = New-Object 'System.Collections.Generic.List[string]'
            $nameProviders[$domain].Add('Input')
        }

        $allNames = @($nameProviders.Keys | Sort-Object)
        $newNames = @($allNames | Where-Object { $_ -ne $domain })
        Write-Status SUCCESS ('Merged scoped names: {0}; concrete subdomains: {1}' -f $allNames.Count, $newNames.Count)

        foreach ($name in $newNames) {
            Write-Status SUCCESS ('NEW DOMAIN: {0} [{1}]' -f $name, ($nameProviders[$name] -join '+'))
        }

        foreach ($name in $allNames) {
            Write-Host ''
            Write-Status INFO ('Checking {0}' -f $name)

            $p80 = Test-TcpPort -Target $name -Port 80
            $p443 = Test-TcpPort -Target $name -Port 443
            $p22 = Test-TcpPort -Target $name -Port 22
            $p3389 = Test-TcpPort -Target $name -Port 3389

            $http = if ($p80.Reachable) { Get-HttpTitle -Scheme http -HostName $name } else { New-EmptyHttpResult }
            $https = if ($p443.Reachable) { Get-HttpTitle -Scheme https -HostName $name } else { New-EmptyHttpResult }

            Write-Status INFO ('RESULT {0}: 80 {1} | 443 {2} | 22 {3} | 3389 {4}' -f $name, $p80.State, $p443.State, $p22.State, $p3389.State)
            if ($http.Title) { Write-Status INFO ('Title(80): {0}' -f $http.Title) }
            if ($https.Title) { Write-Status INFO ('Title(443): {0}' -f $https.Title) }

            $Results.Add([pscustomobject][ordered]@{
                SourceDomain          = $domain
                DiscoveredDomain      = $name
                IsNew                 = ($name -ne $domain)
                DiscoveryProviders    = ($nameProviders[$name] -join '+')
                CrtShSucceeded        = $crtShResult.Succeeded
                CrtShEntryCount       = @($crtShResult.Entries).Count
                CrtShWildcardEvidence = $crtShParsed.WildcardEvidence
                CrtShError            = $crtShResult.Error
                CrtNameSucceeded      = $crtNameResult.Succeeded
                CrtNameNameCount      = $crtNameNames.Count
                CrtNameError          = $crtNameResult.Error
                Port80                = $p80.State
                Port80Detail          = $p80.Detail
                Port443               = $p443.State
                Port443Detail         = $p443.Detail
                Port22                = $p22.State
                Port22Detail          = $p22.Detail
                Port3389              = $p3389.State
                Port3389Detail        = $p3389.Detail
                HttpStatus80          = $http.StatusCode
                RequestedUrl80        = $http.RequestedUrl
                FinalUrl80            = $http.FinalUrl
                Title80               = $http.Title
                HttpError80           = $http.Error
                HttpStatus443         = $https.StatusCode
                RequestedUrl443       = $https.RequestedUrl
                FinalUrl443           = $https.FinalUrl
                Title443              = $https.Title
                HttpError443          = $https.Error
                ObservedAtUtc         = [DateTime]::UtcNow.ToString('o')
            })
        }
    }

    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $outputDirectory -Force)
    }

    $finalResults = @($Results | Sort-Object SourceDomain, DiscoveredDomain -Unique)
    $finalResults | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Status SUCCESS ('Completed. Result rows: {0}; file: {1}' -f $finalResults.Count, $OutputPath)
    Write-Host '========== END ==========' -ForegroundColor Cyan
}
catch {
    Write-Status ERROR $_.Exception.Message
    Write-Host '========== FAILED ==========' -ForegroundColor Red
    exit 1
}
