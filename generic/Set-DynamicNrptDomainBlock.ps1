#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates or removes local Windows NRPT block rules from live RMM and phishing-domain sources.

.DESCRIPTION
    Downloads and normalizes domains from LOLRMM and Phishing.Database at runtime. The complete
    namespace catalog is built, validated, deduplicated, and filtered through a local allow-list
    before Windows NRPT is modified.

    Domains in $AllowedDomains, including their subdomains, are never blocked. Existing rules
    previously created by this script are removed automatically when they become allow-listed.

    NRPT blocking is DNS-based and does not block direct IP connections. The rules are local to
    the current Windows computer and use 127.0.0.1 as the sinkhole DNS server.

.PARAMETER Remove
    Removes only NRPT rules whose Comment exactly equals RMMBlockTest.

.PARAMETER NoProgress
    Suppresses per-domain Added and Skipping messages while retaining stage and summary output.

.EXAMPLE
    .\rmm_nrpt_block.ps1

.EXAMPLE
    .\rmm_nrpt_block.ps1 -Remove

.NOTES
    Tool version: 2.1
#>
[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$NoProgress
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ToolName = 'rmm_nrpt_block.ps1'
$ToolVersion = '2.1'
$Tag = 'RMMBlockTest'
$SinkholeNameServer = '127.0.0.1'

# Local allow-list. Add one DNS domain per line.
# Each entry permits the domain and all of its subdomains.
$AllowedDomains = @(
    'github.com',
	'raw.githubusercontent.com'
)

$Sources = @(
    [pscustomobject]@{
        Name = 'LOLRMM RMM domains'
        Type = 'Csv'
        Uri  = 'https://lolrmm.io/api/rmm_domains.csv'
    },
    [pscustomobject]@{
        Name = 'Phishing.Database permanent domains'
        Type = 'DomainList'
        Uri  = 'https://raw.githubusercontent.com/Phishing-Database/phishing/master/additions/permanent/domains.list'
    }
)

function Write-Status {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('Info', 'Stage', 'Success', 'Warning', 'Error')][string]$Level = 'Info'
    )

    $styles = @{
        Info    = @('[*]', 'Cyan')
        Stage   = @('[>]', 'Blue')
        Success = @('[+]', 'Green')
        Warning = @('[!]', 'Yellow')
        Error   = @('[-]', 'Red')
    }

    $style = $styles[$Level]
    Write-Host "$($style[0]) $Message" -ForegroundColor $style[1]
}

function Test-IsIpAddress {
    param([Parameter(Mandatory = $true)][string]$Value)

    $parsedAddress = $null
    return [System.Net.IPAddress]::TryParse($Value, [ref]$parsedAddress)
}

function ConvertTo-NrptNamespace {
    param([Parameter(Mandatory = $true)][string]$InputValue)

    $original = $InputValue
    $value = $InputValue.Trim()

    if ([string]::IsNullOrWhiteSpace($value)) {
        return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'Empty entry'; Original = $original }
    }

    $value = $value.Trim('"').Trim("'").Trim().ToLowerInvariant()

    if ($value.StartsWith('#') -or $value.StartsWith(';')) {
        return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'Comment entry'; Original = $original }
    }
    if ($value -match '^[a-z][a-z0-9+.-]*://') {
        return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'URL rather than a DNS domain'; Original = $original }
    }
    if ($value.Contains('/') -or $value.Contains('\')) {
        return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'Path or CIDR notation is not supported'; Original = $original }
    }
    if ($value -match ':\d+$') {
        return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'Port-qualified entry is not supported by NRPT'; Original = $original }
    }

    $value = $value.TrimEnd('.')
    if ($value.StartsWith('*.')) {
        $value = $value.Substring(2)
    }
    elseif ($value.StartsWith('.')) {
        $value = $value.Substring(1)
    }

    if (Test-IsIpAddress -Value $value) {
        return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'IP address is not a DNS namespace'; Original = $original }
    }
    if ($value.IndexOfAny([char[]]'*[]{}()+?|^$') -ge 0) {
        return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'Embedded wildcard or regular-expression syntax cannot be represented by NRPT'; Original = $original }
    }
    if ($value.Length -gt 253) {
        return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'Domain exceeds 253 characters'; Original = $original }
    }

    $labels = @($value -split '\.')
    if ($labels.Count -lt 2) {
        return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'Entry is not a fully qualified domain name'; Original = $original }
    }

    foreach ($label in $labels) {
        if ([string]::IsNullOrWhiteSpace($label)) {
            return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'Domain contains an empty label'; Original = $original }
        }
        if ($label.Length -gt 63) {
            return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'Domain label exceeds 63 characters'; Original = $original }
        }
        if ($label -notmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$') {
            return [pscustomobject]@{ IsValid = $false; Namespace = $null; Reason = 'Domain contains unsupported characters or label formatting'; Original = $original }
        }
    }

    return [pscustomobject]@{
        IsValid = $true
        Namespace = ".$value"
        Reason = $null
        Original = $original
    }
}

function Test-IsAllowedNamespace {
    param(
        [Parameter(Mandatory = $true)][string]$Namespace,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$AllowedDomainList
    )

    $candidate = $Namespace.Trim().TrimStart('.').TrimEnd('.').ToLowerInvariant()
    foreach ($allowedEntry in $AllowedDomainList) {
        if ([string]::IsNullOrWhiteSpace($allowedEntry)) { continue }
        $allowed = $allowedEntry.Trim().TrimStart('.').TrimEnd('.').ToLowerInvariant()
        if ($candidate -eq $allowed -or $candidate.EndsWith(".$allowed")) {
            return $true
        }
    }
    return $false
}

function Invoke-TextDownload {
    param(
        [Parameter(Mandatory = $true)][string]$SourceName,
        [Parameter(Mandatory = $true)][string]$Uri
    )

    Write-Status "Downloading source: $SourceName" 'Stage'
    Write-Status "Source URL: $Uri" 'Info'

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Write-Status "Download attempt $attempt of 3..." 'Info'
            $parameters = @{
                Uri = $Uri
                Method = 'Get'
                UseBasicParsing = $true
                TimeoutSec = 60
                ErrorAction = 'Stop'
                Headers = @{ 'User-Agent' = "$ToolName/$ToolVersion" }
            }
            $response = Invoke-WebRequest @parameters
            $content = [string]$response.Content
            if ([string]::IsNullOrWhiteSpace($content)) { throw 'The source returned an empty response.' }
            $byteCount = [System.Text.Encoding]::UTF8.GetByteCount($content)
            Write-Status "Download complete: $byteCount UTF-8 bytes received." 'Success'
            return $content
        }
        catch {
            Write-Status "Download attempt $attempt failed: $($_.Exception.Message)" 'Warning'
            if ($attempt -lt 3) { Start-Sleep -Seconds (2 * $attempt) }
        }
    }

    throw "Unable to download required source '$SourceName' after 3 attempts: $Uri"
}

function Get-LolrmmEntries {
    param([Parameter(Mandatory = $true)][string]$Content)

    Write-Status 'Parsing LOLRMM CSV and selecting the URI column...' 'Stage'
    $rows = @($Content | ConvertFrom-Csv)
    if ($rows.Count -eq 0) { throw 'LOLRMM CSV contained no data rows.' }
    if (-not ($rows[0].PSObject.Properties.Name -contains 'URI')) {
        throw 'LOLRMM CSV does not contain the expected URI column.'
    }
    $entries = @($rows | ForEach-Object { [string]$_.URI })
    Write-Status "LOLRMM rows parsed: $($rows.Count); URI values collected: $($entries.Count)." 'Success'
    return $entries
}

function Get-DomainListEntries {
    param([Parameter(Mandatory = $true)][string]$Content)

    Write-Status 'Parsing Phishing.Database list as one domain per non-comment line...' 'Stage'
    $entries = @(
        $Content -split "`r?`n" |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith('#') -and -not $_.StartsWith(';') }
    )
    if ($entries.Count -eq 0) { throw 'Phishing.Database source contained no usable lines.' }
    Write-Status "Phishing.Database domain lines collected: $($entries.Count)." 'Success'
    return $entries
}

function Add-SourceEntriesToCatalog {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable]$Catalog,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Rejected,
        [Parameter(Mandatory = $true)][string]$SourceName,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries
    )

    Write-Status "Normalizing $($Entries.Count) entries from $SourceName in memory..." 'Stage'
    $accepted = 0
    $duplicates = 0
    $rejectedCount = 0

    foreach ($entry in $Entries) {
        $result = ConvertTo-NrptNamespace -InputValue ([string]$entry)
        if (-not $result.IsValid) {
            $rejectedCount++
            $Rejected.Add([pscustomobject]@{
                Source = $SourceName
                Entry = [string]$result.Original
                Reason = [string]$result.Reason
            }) | Out-Null
            continue
        }

        $key = $result.Namespace.ToLowerInvariant()
        if ($Catalog.ContainsKey($key)) {
            $duplicates++
            if (-not $Catalog[$key].Sources.Contains($SourceName)) {
                $Catalog[$key].Sources.Add($SourceName) | Out-Null
            }
            continue
        }

        $entrySources = New-Object 'System.Collections.Generic.List[string]'
        $entrySources.Add($SourceName) | Out-Null
        $Catalog[$key] = [pscustomobject]@{
            Namespace = [string]$result.Namespace
            Sources = $entrySources
        }
        $accepted++
    }

    Write-Status "Normalization complete for ${SourceName}: accepted=$accepted; duplicates=$duplicates; rejected=$rejectedCount." 'Success'
}

Write-Host ''
Write-Status "$ToolName v$ToolVersion" 'Info'
Write-Status "NRPT rule tag: $Tag" 'Info'
Write-Status "Sinkhole DNS server: $SinkholeNameServer" 'Info'
Write-Status 'Blocked domains are downloaded live; the local allow-list is intentionally hard-coded and user-editable.' 'Info'
Write-Status "Local allow-list entries: $($AllowedDomains.Count)" 'Info'
foreach ($allowedDomain in $AllowedDomains) {
    Write-Status "Allow-listed domain and subdomains: $allowedDomain" 'Success'
}
Write-Host ''

if ($Remove) {
    Write-Status "Removal mode selected. Searching for rules tagged '$Tag'..." 'Stage'
    $rulesToRemove = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -eq $Tag })
    if ($rulesToRemove.Count -eq 0) {
        Write-Status 'No matching NRPT rules were found. Nothing to remove.' 'Warning'
        exit 0
    }

    $removed = 0
    $failedRemovals = 0
    foreach ($rule in $rulesToRemove) {
        try {
            Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop
            $removed++
            Write-Status "Removed NRPT rule: $($rule.Name) [$($rule.Namespace -join ', ')]" 'Success'
        }
        catch {
            $failedRemovals++
            Write-Status "Failed to remove NRPT rule $($rule.Name): $($_.Exception.Message)" 'Error'
        }
    }

    Write-Status "Removal complete: removed=$removed; failed=$failedRemovals." $(if ($failedRemovals -eq 0) { 'Success' } else { 'Warning' })
    Write-Status "Confirm with: Get-DnsClientNrptRule | Where-Object Comment -eq '$Tag'" 'Info'
    if ($failedRemovals -gt 0) { exit 1 }
    exit 0
}

# Validate and normalize the allow-list before downloading or changing anything.
Write-Status 'Validating and normalizing the local allow-list...' 'Stage'
$normalizedAllowedDomains = New-Object 'System.Collections.Generic.List[string]'
foreach ($allowedDomain in $AllowedDomains) {
    $allowedResult = ConvertTo-NrptNamespace -InputValue ([string]$allowedDomain)
    if (-not $allowedResult.IsValid) {
        throw "Invalid allow-list entry '$allowedDomain': $($allowedResult.Reason). No NRPT rules were changed."
    }
    $normalizedAllowed = $allowedResult.Namespace.TrimStart('.').ToLowerInvariant()
    if (-not $normalizedAllowedDomains.Contains($normalizedAllowed)) {
        $normalizedAllowedDomains.Add($normalizedAllowed) | Out-Null
    }
}
Write-Status "Validated allow-list entries: $($normalizedAllowedDomains.Count)." 'Success'

$catalog = @{}
$rejectedEntries = New-Object 'System.Collections.Generic.List[object]'

foreach ($source in $Sources) {
    Write-Host ''
    $content = Invoke-TextDownload -SourceName $source.Name -Uri $source.Uri
    if ($source.Type -eq 'Csv') {
        $entries = @(Get-LolrmmEntries -Content $content)
    }
    elseif ($source.Type -eq 'DomainList') {
        $entries = @(Get-DomainListEntries -Content $content)
    }
    else {
        throw "Unsupported source type: $($source.Type)"
    }
    Add-SourceEntriesToCatalog -Catalog $catalog -Rejected $rejectedEntries -SourceName $source.Name -Entries $entries
}

Write-Host ''
Write-Status 'Removing allow-listed domains and their subdomains from the in-memory block catalog...' 'Stage'
$allowListedCatalogKeys = @(
    $catalog.Keys | Where-Object {
        Test-IsAllowedNamespace -Namespace $_ -AllowedDomainList $normalizedAllowedDomains.ToArray()
    }
)
foreach ($allowListedKey in $allowListedCatalogKeys) {
    Write-Status "Excluded by local allow-list: $($catalog[$allowListedKey].Namespace)" 'Success'
    $catalog.Remove($allowListedKey)
}
Write-Status "Namespaces excluded by local allow-list: $($allowListedCatalogKeys.Count)." 'Success'

Write-Status 'Validating the completed in-memory namespace catalog...' 'Stage'
$namespaces = @($catalog.Values | ForEach-Object { $_.Namespace } | Sort-Object -Unique)
if ($namespaces.Count -eq 0) { throw 'No valid NRPT namespaces were produced. No rules were changed.' }

$finalFailures = @(
    $namespaces | Where-Object {
        $_ -notmatch '^\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    }
)
if ($finalFailures.Count -gt 0) {
    throw "Final validation failed for $($finalFailures.Count) entries. No rules were changed. First invalid entry: $($finalFailures[0])"
}
Write-Status "In-memory catalog ready: $($namespaces.Count) unique, validated NRPT namespaces." 'Success'
Write-Status "Rejected unsupported source entries: $($rejectedEntries.Count)." $(if ($rejectedEntries.Count -eq 0) { 'Info' } else { 'Warning' })

if ($rejectedEntries.Count -gt 0) {
    foreach ($group in @($rejectedEntries | Group-Object Reason | Sort-Object Count -Descending)) {
        Write-Status "Rejected: $($group.Count) - $($group.Name)" 'Warning'
    }
    Write-Status 'Showing up to the first 10 rejected examples:' 'Info'
    foreach ($rejected in @($rejectedEntries | Select-Object -First 10)) {
        Write-Status "Rejected from $($rejected.Source): '$($rejected.Entry)' - $($rejected.Reason)" 'Warning'
    }
}

Write-Host ''
Write-Status 'Reading existing Windows NRPT rules...' 'Stage'
$existingRules = @(Get-DnsClientNrptRule -ErrorAction Stop)
$existingNamespaces = @{}
foreach ($rule in $existingRules) {
    foreach ($namespace in @($rule.Namespace)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$namespace)) {
            $namespaceKey = ([string]$namespace).ToLowerInvariant()
            $existingNamespaces[$namespaceKey] = [string]$rule.Name
        }
    }
}
Write-Status "Existing NRPT rules read: $($existingRules.Count); indexed namespaces: $($existingNamespaces.Count)." 'Success'

# Remove old rules created by this script if they are now allow-listed.
Write-Status 'Reconciling existing script-created rules against the local allow-list...' 'Stage'
$allowListedRulesRemoved = 0
$allowListedRuleRemovalFailures = 0
foreach ($rule in $existingRules) {
    if ($rule.Comment -ne $Tag) { continue }

    $allowedMatches = @(
        @($rule.Namespace) | Where-Object {
            Test-IsAllowedNamespace -Namespace ([string]$_) -AllowedDomainList $normalizedAllowedDomains.ToArray()
        }
    )
    if ($allowedMatches.Count -eq 0) { continue }

    try {
        Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop
        $allowListedRulesRemoved++
        foreach ($removedNamespace in @($rule.Namespace)) {
            $removedKey = ([string]$removedNamespace).ToLowerInvariant()
            if ($existingNamespaces.ContainsKey($removedKey)) {
                $existingNamespaces.Remove($removedKey)
            }
        }
        Write-Status "Removed previously blocked allow-listed rule: $($rule.Namespace -join ', ')" 'Success'
    }
    catch {
        $allowListedRuleRemovalFailures++
        Write-Status "Failed to remove allow-listed rule $($rule.Name): $($_.Exception.Message)" 'Error'
    }
}
Write-Status "Previously blocked allow-listed rules removed: $allowListedRulesRemoved; failures: $allowListedRuleRemovalFailures." $(if ($allowListedRuleRemovalFailures -eq 0) { 'Success' } else { 'Warning' })

Write-Host ''
Write-Status "Applying $($namespaces.Count) validated namespaces to Windows NRPT..." 'Stage'
$addedCount = 0
$skippedCount = 0
$failedCount = 0

foreach ($namespace in $namespaces) {
    $key = $namespace.ToLowerInvariant()
    if ($existingNamespaces.ContainsKey($key)) {
        $skippedCount++
        if (-not $NoProgress) { Write-Status "Skipping existing namespace: $namespace" 'Warning' }
        continue
    }

    try {
        Add-DnsClientNrptRule `
            -Namespace $namespace `
            -NameServers $SinkholeNameServer `
            -Comment $Tag `
            -DisplayName "Domain block: $namespace" `
            -ErrorAction Stop | Out-Null

        $existingNamespaces[$key] = $true
        $addedCount++
        if (-not $NoProgress) {
            $sourceText = @($catalog[$key].Sources.ToArray()) -join '; '
            Write-Status "Added NRPT block rule: $namespace [source: $sourceText]" 'Success'
        }
    }
    catch {
        $failedCount++
        Write-Status "Failed to add NRPT rule for ${namespace}: $($_.Exception.Message)" 'Error'
    }
}

Write-Host ''
Write-Status 'Completed NRPT processing.' 'Stage'
Write-Status "Unique validated namespaces after allow-list: $($namespaces.Count)" 'Info'
Write-Status "Added: $addedCount" 'Success'
Write-Status "Skipped because already present: $skippedCount" 'Warning'
Write-Status "Failed: $failedCount" $(if ($failedCount -eq 0) { 'Success' } else { 'Error' })
Write-Status "Rejected during source normalization: $($rejectedEntries.Count)" 'Info'
Write-Status "Excluded by local allow-list: $($allowListedCatalogKeys.Count)" 'Success'
Write-Status "Previously blocked allow-listed rules removed: $allowListedRulesRemoved" 'Success'
Write-Host ''
Write-Status "Review rules with: Get-DnsClientNrptRule | Where-Object Comment -eq '$Tag'" 'Info'
Write-Status "Remove rules with: .\rmm_nrpt_block.ps1 -Remove" 'Info'
Write-Status "Test GitHub with: Resolve-DnsName 'github.com'" 'Info'

if ($failedCount -gt 0 -or $allowListedRuleRemovalFailures -gt 0) { exit 1 }
exit 0
