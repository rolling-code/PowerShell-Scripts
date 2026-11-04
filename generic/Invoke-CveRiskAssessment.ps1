#requires -Version 7.2
<#
.SYNOPSIS
    Enriches a text list of CVE identifiers with current CISA KEV, FIRST EPSS, and NVD evidence.
.DESCRIPTION
    Downloads the latest CISA Known Exploited Vulnerabilities JSON catalog and the current
    FIRST EPSS daily CSV, validates and deduplicates CVE identifiers from a text file, retrieves
    NVD CVSS and description data, and exports evidence-focused CSV, JSON, and Excel reports.

    Threat intelligence is kept separate from applicability and business context. Optional
    optional asset-context CSV input can supply presence, version, exposure, reachability, prerequisites,
    compensating controls, and criticality. Missing context remains Unknown and is never invented.

    This product uses data from the NVD API but is not endorsed or certified by the NVD.
.VERSION
    2.1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CveListPath,

    [string]$ContextCsvPath,

    [string]$OutputDirectory = (Join-Path $PWD ('CveRiskAssessment-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [string]$CacheDirectory = (Join-Path $env:LOCALAPPDATA 'CveRiskAssessment\Cache'),

    [ValidateRange(0, 168)]
    [int]$MaximumCacheAgeHours = 24,

    [string]$NvdApiKey = $env:NVD_API_KEY,

    [switch]$SkipNvd,
    [switch]$DoNotInstallMissingModules,
    [switch]$ForceFeedRefresh
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ScriptVersion = '2.1.0'
$StartedUtc = [datetime]::UtcNow
$UserAgent = "Invoke-CveRiskAssessment/$ScriptVersion"
$KevUri = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
$EpssUri = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'
$NvdBaseUri = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
$SourceUrls = [ordered]@{
    CisaKev = $KevUri
    FirstEpss = $EpssUri
    NvdCveApi = $NvdBaseUri
}
$Errors = [System.Collections.Generic.List[object]]::new()

function Write-Stage { param([string]$Message) Write-Host ('[{0}] [STEP] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Cyan }
function Write-InfoMessage { param([string]$Message) Write-Host ('[{0}] [INFO] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Gray }
function Write-Pass { param([string]$Message) Write-Host ('[{0}] [PASS] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Green }
function Write-WarnMessage { param([string]$Message) Write-Host ('[{0}] [WARN] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Yellow }
function Write-Fail { param([string]$Message) Write-Host ('[{0}] [FAIL] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Red }

function Get-SafeProperty {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $Property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $null }
    return $Property.Value
}

function Add-CollectionError {
    param([string]$Stage, [string]$CveId, [string]$Message)
    $Errors.Add([pscustomobject]@{
        TimestampUtc = [datetime]::UtcNow.ToString('o')
        Stage = $Stage
        CveId = $CveId
        Message = $Message
    })
}

function Ensure-Module {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        if ($DoNotInstallMissingModules) { throw "Required module '$Name' is not installed." }
        Write-WarnMessage "Installing missing module '$Name' for the current user."
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $Name -ErrorAction Stop
}

function Test-CacheFresh {
    param([Parameter(Mandatory)][string]$Path)
    if ($ForceFeedRefresh -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $Age = [datetime]::UtcNow - (Get-Item -LiteralPath $Path).LastWriteTimeUtc
    return $Age.TotalHours -le $MaximumCacheAgeHours
}

function Save-RemoteFile {
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Destination, [Parameter(Mandatory)][string]$Label)
    if (Test-CacheFresh -Path $Destination) {
        Write-Pass "$Label cache is current: $Destination"
        return
    }
    Write-InfoMessage "Downloading $Label from $Uri"
    $TemporaryPath = "$Destination.download"
    Invoke-WebRequest -Uri $Uri -OutFile $TemporaryPath -UserAgent $UserAgent -MaximumRedirection 10
    if (-not (Test-Path -LiteralPath $TemporaryPath) -or (Get-Item -LiteralPath $TemporaryPath).Length -eq 0) {
        throw "$Label download was empty."
    }
    Move-Item -LiteralPath $TemporaryPath -Destination $Destination -Force
    Write-Pass "$Label downloaded: $Destination"
}

function Expand-GzipFile {
    param([Parameter(Mandatory)][string]$SourcePath, [Parameter(Mandatory)][string]$DestinationPath)
    $InputStream = [System.IO.File]::OpenRead($SourcePath)
    try {
        $GzipStream = [System.IO.Compression.GzipStream]::new($InputStream, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $OutputStream = [System.IO.File]::Create($DestinationPath)
            try { $GzipStream.CopyTo($OutputStream) }
            finally { $OutputStream.Dispose() }
        }
        finally { $GzipStream.Dispose() }
    }
    finally { $InputStream.Dispose() }
}

function Get-EnglishDescription {
    param($CveObject)
    foreach ($Description in @(Get-SafeProperty $CveObject 'descriptions')) {
        if ([string](Get-SafeProperty $Description 'lang') -eq 'en') { return [string](Get-SafeProperty $Description 'value') }
    }
    return ''
}

function Get-PrimaryCvss {
    param($Metrics)
    $Candidates = @(
        @{ Name='cvssMetricV40'; Version='4.0' },
        @{ Name='cvssMetricV31'; Version='3.1' },
        @{ Name='cvssMetricV30'; Version='3.0' },
        @{ Name='cvssMetricV2'; Version='2.0' }
    )
    foreach ($Candidate in $Candidates) {
        $Entries = @(Get-SafeProperty $Metrics $Candidate.Name)
        if ($Entries.Count -eq 0) { continue }
        $Preferred = @($Entries | Where-Object { [string](Get-SafeProperty $_ 'type') -eq 'Primary' } | Select-Object -First 1)
        $Entry = if ($Preferred.Count -gt 0) { $Preferred[0] } else { $Entries[0] }
        $CvssData = Get-SafeProperty $Entry 'cvssData'
        if ($null -eq $CvssData) { continue }
        return [pscustomobject]@{
            Version = $Candidate.Version
            BaseScore = Get-SafeProperty $CvssData 'baseScore'
            Severity = Get-SafeProperty $CvssData 'baseSeverity'
            Vector = Get-SafeProperty $CvssData 'vectorString'
            Source = Get-SafeProperty $Entry 'source'
        }
    }
    return [pscustomobject]@{ Version=''; BaseScore=$null; Severity=''; Vector=''; Source='' }
}

function Get-NvdEvidence {
    param([Parameter(Mandatory)][string]$CveId, [Parameter(Mandatory)][int]$Position, [Parameter(Mandatory)][int]$Total)
    if ($SkipNvd) { return $null }
    Write-InfoMessage "[$Position/$Total] Retrieving NVD record for $CveId"
    $Headers = @{ 'User-Agent' = $UserAgent }
    if (-not [string]::IsNullOrWhiteSpace($NvdApiKey)) { $Headers.apiKey = $NvdApiKey }
    $Uri = "${NvdBaseUri}?cveId=$([uri]::EscapeDataString($CveId))"
    try {
        $Response = Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -MaximumRetryCount 3 -RetryIntervalSec 2
        $Vulnerabilities = @(Get-SafeProperty $Response 'vulnerabilities')
        if ($Vulnerabilities.Count -eq 0) { return $null }
        return Get-SafeProperty $Vulnerabilities[0] 'cve'
    }
    catch {
        Add-CollectionError -Stage 'NVD' -CveId $CveId -Message $_.Exception.Message
        Write-WarnMessage "NVD lookup failed for $CveId; continuing."
        return $null
    }
    finally {
        if ($Position -lt $Total) {
            $Delay = if ([string]::IsNullOrWhiteSpace($NvdApiKey)) { 6.1 } else { 0.7 }
            Start-Sleep -Milliseconds ([int]($Delay * 1000))
        }
    }
}

function Normalize-ContextValue {
    param([AllowNull()]$Value, [string[]]$Allowed, [string]$Default='Unknown')
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $Default }
    foreach ($Candidate in $Allowed) {
        if ([string]$Value -ieq $Candidate) { return $Candidate }
    }
    return $Default
}

function Get-ContextForCve {
    param([string]$CveId, [hashtable]$ContextMap)
    if ($ContextMap.ContainsKey($CveId)) { return $ContextMap[$CveId] }
    return $null
}

function Get-ApplicabilityDisposition {
    param([string]$ComponentPresence, [string]$AffectedVersion, [string]$Reachability, [string]$ExploitPrerequisites)
    if ($ComponentPresence -eq 'NotDetected' -or $AffectedVersion -eq 'NotConfirmed' -or $Reachability -eq 'NotReachable' -or $ExploitPrerequisites -eq 'NotMet') { return 'NotConfirmed' }
    if ($ComponentPresence -eq 'Confirmed' -and $AffectedVersion -eq 'Confirmed' -and $Reachability -eq 'Confirmed' -and $ExploitPrerequisites -eq 'Met') { return 'Confirmed' }
    if (($ComponentPresence -eq 'Confirmed' -or $AffectedVersion -eq 'Confirmed') -and $Reachability -ne 'NotReachable') { return 'LikelyOrProbable' }
    return 'Inconclusive'
}

function Get-ContextualPriority {
    param(
        [bool]$IsKev,
        [AllowNull()][Nullable[double]]$Epss,
        [AllowNull()][Nullable[double]]$Percentile,
        [AllowNull()][Nullable[double]]$CvssBaseScore,
        [string]$CvssSeverity,
        [string]$Applicability,
        [string]$AssetExposure,
        [string]$CompensatingControls,
        [string]$BusinessCriticality
    )

    if ($Applicability -eq 'NotConfirmed') { return 'DEPRIORITIZE_PENDING_NEW_EVIDENCE' }

    $Score = 0
    if ($IsKev) { $Score += 5 }
    if ($null -ne $Epss) {
        if ($Epss -ge 0.50) { $Score += 4 }
        elseif ($Epss -ge 0.10) { $Score += 3 }
        elseif ($Epss -ge 0.02) { $Score += 2 }
        elseif ($Epss -ge 0.005) { $Score += 1 }
    }
    if ($null -ne $Percentile -and $Percentile -ge 0.95) { $Score += 1 }
    if ($Applicability -eq 'Confirmed') { $Score += 4 }
    elseif ($Applicability -eq 'LikelyOrProbable') { $Score += 2 }
    if ($AssetExposure -eq 'Internet') { $Score += 2 }
    elseif ($AssetExposure -eq 'Internal') { $Score += 1 }
    if ($BusinessCriticality -eq 'Critical') { $Score += 2 }
    elseif ($BusinessCriticality -eq 'High') { $Score += 1 }
    if ($CompensatingControls -eq 'Strong') { $Score -= 2 }
    elseif ($CompensatingControls -eq 'Partial') { $Score -= 1 }

    if ($Applicability -eq 'Inconclusive') {
        if ($IsKev -or $Score -ge 7) { return 'VALIDATE_URGENTLY' }
        return 'VALIDATE'
    }

    # Prevent confirmed applicability by itself from inflating a medium-severity,
    # non-KEV, low-EPSS issue to P2. P2 requires at least one material threat,
    # severity, or business-impact signal in addition to the aggregate score.
    $HasP2Signal = $IsKev -or
        ($null -ne $Epss -and $Epss -ge 0.10) -or
        ($null -ne $CvssBaseScore -and $CvssBaseScore -ge 7.0) -or
        ($CvssSeverity -in @('HIGH','CRITICAL')) -or
        ($BusinessCriticality -in @('High','Critical'))

    $HasP1Signal = $IsKev -and (
        ($null -ne $CvssBaseScore -and $CvssBaseScore -ge 9.0) -or
        ($CvssSeverity -eq 'CRITICAL') -or
        ($BusinessCriticality -eq 'Critical')
    )

    if ($Score -ge 11 -and $HasP1Signal) { return 'P1_CRITICAL' }
    if ($Score -ge 8 -and $HasP2Signal) { return 'P2_HIGH' }
    if ($Score -ge 5) { return 'P3_MEDIUM' }
    return 'P4_LOW'
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ' CVE Evidence and Risk Assessment' -ForegroundColor White
Write-Host " Version: $ScriptVersion" -ForegroundColor White
Write-Host ' Mode: READ-ONLY ENRICHMENT' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ''
Write-InfoMessage "Identity: $([Environment]::UserDomainName)\$([Environment]::UserName)"
Write-InfoMessage "Computer: $env:COMPUTERNAME"
Write-InfoMessage "Input file: $CveListPath"
Write-InfoMessage 'No asset, vulnerability, ticket, or remote system will be modified.'

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$CacheDirectory = (Resolve-Path -LiteralPath $CacheDirectory).Path

Write-Stage 'Reading and validating CVE input.'
$RawLines = @(Get-Content -LiteralPath $CveListPath)
$ValidCves = [System.Collections.Generic.List[string]]::new()
$InvalidLines = [System.Collections.Generic.List[object]]::new()
$LineNumber = 0
foreach ($Line in $RawLines) {
    $LineNumber++
    $Trimmed = ([string]$Line).Trim()
    if ([string]::IsNullOrWhiteSpace($Trimmed) -or $Trimmed.StartsWith('#')) { continue }
    $Candidate = (($Trimmed -split '[,|;\s]')[0]).ToUpperInvariant()
    if ($Candidate -match '^CVE-\d{4}-\d{4,}$') { $ValidCves.Add($Candidate) }
    else { $InvalidLines.Add([pscustomobject]@{ LineNumber=$LineNumber; Input=$Trimmed; Reason='Invalid CVE identifier format' }) }
}
$Cves = @($ValidCves | Sort-Object -Unique)
if ($Cves.Count -eq 0) { throw 'No valid CVE identifiers were found in the input file.' }
Write-Pass "Valid unique CVEs: $($Cves.Count)"
if ($InvalidLines.Count -gt 0) { Write-WarnMessage "Invalid input lines: $($InvalidLines.Count)" }

$ContextMap = @{}
if (-not [string]::IsNullOrWhiteSpace($ContextCsvPath)) {
    if (-not (Test-Path -LiteralPath $ContextCsvPath -PathType Leaf)) { throw "Context CSV was not found: $ContextCsvPath" }
    Write-Stage 'Loading optional asset context.'
    foreach ($Row in @(Import-Csv -LiteralPath $ContextCsvPath)) {
        $ContextCve = ([string](Get-SafeProperty $Row 'CVE')).ToUpperInvariant()
        if ($ContextCve -match '^CVE-\d{4}-\d{4,}$' -and -not $ContextMap.ContainsKey($ContextCve)) { $ContextMap[$ContextCve] = $Row }
    }
    Write-Pass "Context rows loaded: $($ContextMap.Count)"
} else {
    $TemplatePath = Join-Path $OutputDirectory 'Asset-Context-Template.csv'
    @([pscustomobject]@{
        CVE='CVE-YYYY-NNNN'; Asset='example-host'; AssetExposure='Unknown'; AffectedVersion='Unknown';
        Reachability='Unknown'; ExploitPrerequisites='Unknown'; CompensatingControls='Unknown';
        ComponentPresence='Unknown'; BusinessCriticality='Unknown'; Evidence=''; EvidenceSource=''
    }) | Export-Csv -LiteralPath $TemplatePath -NoTypeInformation -Encoding utf8
    Write-InfoMessage "No context CSV supplied. A reusable template was created: $TemplatePath"
}

Write-Stage 'Downloading or reusing authoritative threat-intelligence feeds.'
$KevPath = Join-Path $CacheDirectory 'known_exploited_vulnerabilities.json'
$EpssGzipPath = Join-Path $CacheDirectory 'epss_scores-current.csv.gz'
$EpssCsvPath = Join-Path $CacheDirectory 'epss_scores-current.csv'
Save-RemoteFile -Uri $KevUri -Destination $KevPath -Label 'CISA KEV JSON catalog'
Save-RemoteFile -Uri $EpssUri -Destination $EpssGzipPath -Label 'FIRST EPSS daily CSV'
$EpssCsvExists = Test-Path -LiteralPath $EpssCsvPath -PathType Leaf
$EpssCsvIsOlder = if ($EpssCsvExists) {
    (Get-Item -LiteralPath $EpssGzipPath).LastWriteTimeUtc -gt (Get-Item -LiteralPath $EpssCsvPath).LastWriteTimeUtc
} else {
    $true
}
if ($ForceFeedRefresh -or -not $EpssCsvExists -or $EpssCsvIsOlder) {
    Write-InfoMessage 'Decompressing EPSS CSV.'
    Expand-GzipFile -SourcePath $EpssGzipPath -DestinationPath $EpssCsvPath
}

Write-Stage 'Loading CISA KEV and FIRST EPSS evidence.'
$KevDocument = Get-Content -LiteralPath $KevPath -Raw | ConvertFrom-Json
$KevEntries = @(Get-SafeProperty $KevDocument 'vulnerabilities')
$KevByCve = @{}
foreach ($Entry in $KevEntries) { $KevByCve[[string](Get-SafeProperty $Entry 'cveID')] = $Entry }

# FIRST's daily EPSS file begins with a metadata comment before the CSV header.
# Remove comment and blank lines before parsing so cve, epss, and percentile map correctly.
$EpssDataLines = @(Get-Content -LiteralPath $EpssCsvPath | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith('#')
})
if ($EpssDataLines.Count -lt 2) { throw 'The FIRST EPSS CSV did not contain a header and data rows.' }
$EpssRows = @($EpssDataLines | ConvertFrom-Csv)
$EpssByCve = @{}
foreach ($Entry in $EpssRows) {
    $Id = [string](Get-SafeProperty $Entry 'cve')
    if (-not [string]::IsNullOrWhiteSpace($Id)) { $EpssByCve[$Id] = $Entry }
}
Write-Pass "KEV entries loaded: $($KevByCve.Count)"
Write-Pass "EPSS entries loaded: $($EpssByCve.Count)"

$Results = [System.Collections.Generic.List[object]]::new()
$Index = 0
foreach ($CveId in $Cves) {
    $Index++
    $Percent = [math]::Round(($Index / $Cves.Count) * 100, 1)
    Write-Host ('[{0}] [{1}/{2} - {3}%] Assessing {4}' -f (Get-Date -Format 'HH:mm:ss'), $Index, $Cves.Count, $Percent, $CveId) -ForegroundColor DarkCyan

    $KevEntry = if ($KevByCve.ContainsKey($CveId)) { $KevByCve[$CveId] } else { $null }
    $EpssEntry = if ($EpssByCve.ContainsKey($CveId)) { $EpssByCve[$CveId] } else { $null }
    $EpssScore = if ($EpssEntry) { [double](Get-SafeProperty $EpssEntry 'epss') } else { $null }
    $EpssPercentile = if ($EpssEntry) { [double](Get-SafeProperty $EpssEntry 'percentile') } else { $null }
    $NvdCve = Get-NvdEvidence -CveId $CveId -Position $Index -Total $Cves.Count
    $Cvss = if ($NvdCve) { Get-PrimaryCvss -Metrics (Get-SafeProperty $NvdCve 'metrics') } else { [pscustomobject]@{ Version=''; BaseScore=$null; Severity=''; Vector=''; Source='' } }
    $Context = Get-ContextForCve -CveId $CveId -ContextMap $ContextMap

    $Asset = if ($Context) { [string](Get-SafeProperty $Context 'Asset') } else { '' }
    $AssetExposure = Normalize-ContextValue (Get-SafeProperty $Context 'AssetExposure') @('Internet','Internal','Isolated','Unknown')
    $AffectedVersion = Normalize-ContextValue (Get-SafeProperty $Context 'AffectedVersion') @('Confirmed','NotConfirmed','Unknown')
    $Reachability = Normalize-ContextValue (Get-SafeProperty $Context 'Reachability') @('Confirmed','NotReachable','Unknown')
    $ExploitPrerequisites = Normalize-ContextValue (Get-SafeProperty $Context 'ExploitPrerequisites') @('Met','NotMet','Unknown')
    $CompensatingControls = Normalize-ContextValue (Get-SafeProperty $Context 'CompensatingControls') @('None','Partial','Strong','Unknown')
    $ComponentPresence = Normalize-ContextValue (Get-SafeProperty $Context 'ComponentPresence') @('Confirmed','NotDetected','Unknown')
    $BusinessCriticality = Normalize-ContextValue (Get-SafeProperty $Context 'BusinessCriticality') @('Critical','High','Medium','Low','Unknown')
    $Applicability = Get-ApplicabilityDisposition -ComponentPresence $ComponentPresence -AffectedVersion $AffectedVersion -Reachability $Reachability -ExploitPrerequisites $ExploitPrerequisites
    $Priority = Get-ContextualPriority -IsKev ($null -ne $KevEntry) -Epss $EpssScore -Percentile $EpssPercentile -CvssBaseScore $Cvss.BaseScore -CvssSeverity ([string]$Cvss.Severity).ToUpperInvariant() -Applicability $Applicability -AssetExposure $AssetExposure -CompensatingControls $CompensatingControls -BusinessCriticality $BusinessCriticality

    $Results.Add([pscustomobject][ordered]@{
        CVE = $CveId
        Asset = $Asset
        NvdStatus = if ($NvdCve) { Get-SafeProperty $NvdCve 'vulnStatus' } else { 'NotReturned' }
        Published = if ($NvdCve) { Get-SafeProperty $NvdCve 'published' } else { $null }
        LastModified = if ($NvdCve) { Get-SafeProperty $NvdCve 'lastModified' } else { $null }
        Description = if ($NvdCve) { Get-EnglishDescription $NvdCve } else { '' }
        CvssVersion = $Cvss.Version
        CvssBaseScore = $Cvss.BaseScore
        CvssSeverity = $Cvss.Severity
        CvssVector = $Cvss.Vector
        CvssSource = $Cvss.Source
        CisaKev = $null -ne $KevEntry
        KevDateAdded = if ($KevEntry) { Get-SafeProperty $KevEntry 'dateAdded' } else { $null }
        KevDueDate = if ($KevEntry) { Get-SafeProperty $KevEntry 'dueDate' } else { $null }
        KevKnownRansomwareCampaignUse = if ($KevEntry) { Get-SafeProperty $KevEntry 'knownRansomwareCampaignUse' } else { '' }
        KevRequiredAction = if ($KevEntry) { Get-SafeProperty $KevEntry 'requiredAction' } else { '' }
        KevVendorProject = if ($KevEntry) { Get-SafeProperty $KevEntry 'vendorProject' } else { '' }
        KevProduct = if ($KevEntry) { Get-SafeProperty $KevEntry 'product' } else { '' }
        EpssScore = $EpssScore
        EpssProbabilityPercent = if ($null -ne $EpssScore) { [math]::Round($EpssScore * 100, 4) } else { $null }
        EpssPercentile = $EpssPercentile
        EpssPercentilePercent = if ($null -ne $EpssPercentile) { [math]::Round($EpssPercentile * 100, 4) } else { $null }
        EpssDate = if ($EpssEntry) { Get-SafeProperty $EpssEntry 'date' } else { $null }
        ComponentPresence = $ComponentPresence
        AffectedVersion = $AffectedVersion
        AssetExposure = $AssetExposure
        Reachability = $Reachability
        ExploitPrerequisites = $ExploitPrerequisites
        CompensatingControls = $CompensatingControls
        BusinessCriticality = $BusinessCriticality
        ApplicabilityDisposition = $Applicability
        ContextualPriority = $Priority
        Evidence = if ($Context) { Get-SafeProperty $Context 'Evidence' } else { '' }
        EvidenceSource = if ($Context) { Get-SafeProperty $Context 'EvidenceSource' } else { '' }
        AssessmentLimitation = if ($Context) { 'Context supplied by operator; validate evidence before remediation.' } else { 'No asset context supplied. Threat intelligence does not prove component presence, affected version, reachability, exploit prerequisites, or business impact.' }
        CisaKevSource = $KevUri
        FirstEpssSource = $EpssUri
        NvdSource = "${NvdBaseUri}?cveId=$CveId"
    })
}

$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$CsvPath = Join-Path $OutputDirectory "CveRiskAssessment-$Timestamp.csv"
$JsonPath = Join-Path $OutputDirectory "CveRiskAssessment-$Timestamp.json"
$XlsxPath = Join-Path $OutputDirectory "CveRiskAssessment-$Timestamp.xlsx"
$ManifestPath = Join-Path $OutputDirectory "Feed-Manifest-$Timestamp.json"
$InvalidPath = Join-Path $OutputDirectory "Invalid-Input-$Timestamp.csv"
$ErrorPath = Join-Path $OutputDirectory "Collection-Errors-$Timestamp.csv"

Write-Stage 'Exporting structured evidence.'
$ResultArray = $Results.ToArray()
$ResultArray | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding utf8
$ResultArray | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $JsonPath -Encoding utf8
if ($InvalidLines.Count -gt 0) { $InvalidLines.ToArray() | Export-Csv -LiteralPath $InvalidPath -NoTypeInformation -Encoding utf8 }
if ($Errors.Count -gt 0) { $Errors.ToArray() | Export-Csv -LiteralPath $ErrorPath -NoTypeInformation -Encoding utf8 }

$FeedManifest = [ordered]@{
    ScriptVersion = $ScriptVersion
    GeneratedUtc = [datetime]::UtcNow.ToString('o')
    Identity = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
    Sources = $SourceUrls
    CisaKev = [ordered]@{ Path=$KevPath; LastWriteUtc=(Get-Item $KevPath).LastWriteTimeUtc.ToString('o'); SHA256=(Get-FileHash $KevPath -Algorithm SHA256).Hash; CatalogVersion=(Get-SafeProperty $KevDocument 'catalogVersion'); DateReleased=(Get-SafeProperty $KevDocument 'dateReleased'); Count=$KevByCve.Count }
    FirstEpss = [ordered]@{ Path=$EpssCsvPath; LastWriteUtc=(Get-Item $EpssCsvPath).LastWriteTimeUtc.ToString('o'); SHA256=(Get-FileHash $EpssCsvPath -Algorithm SHA256).Hash; Count=$EpssByCve.Count }
    Nvd = [ordered]@{ ApiBase=$NvdBaseUri; Skipped=[bool]$SkipNvd; ApiKeyUsed=-not [string]::IsNullOrWhiteSpace($NvdApiKey); Notice='This product uses data from the NVD API but is not endorsed or certified by the NVD.' }
    Input = [ordered]@{ Path=(Resolve-Path $CveListPath).Path; SHA256=(Get-FileHash $CveListPath -Algorithm SHA256).Hash; ValidUniqueCves=$Cves.Count; InvalidLines=$InvalidLines.Count }
}
$FeedManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ManifestPath -Encoding utf8

Ensure-Module -Name 'ImportExcel'
$Summary = @(
    [pscustomobject]@{ Metric='ScriptVersion'; Value=$ScriptVersion; Interpretation='Assessment version' },
    [pscustomobject]@{ Metric='GeneratedUtc'; Value=[datetime]::UtcNow.ToString('o'); Interpretation='Evidence generation time' },
    [pscustomobject]@{ Metric='InputCves'; Value=$Cves.Count; Interpretation='Valid unique CVE identifiers assessed' },
    [pscustomobject]@{ Metric='CisaKevMatches'; Value=@($ResultArray | Where-Object CisaKev).Count; Interpretation='Confirmed inclusion in the current CISA KEV catalog' },
    [pscustomobject]@{ Metric='EpssMatches'; Value=@($ResultArray | Where-Object { $null -ne $_.EpssScore }).Count; Interpretation='CVEs with a current FIRST EPSS score' },
    [pscustomobject]@{ Metric='NvdMatches'; Value=@($ResultArray | Where-Object NvdStatus -ne 'NotReturned').Count; Interpretation='CVEs returned by the NVD API' },
    [pscustomobject]@{ Metric='ConfirmedApplicability'; Value=@($ResultArray | Where-Object ApplicabilityDisposition -eq 'Confirmed').Count; Interpretation='Requires operator-supplied context and evidence' },
    [pscustomobject]@{ Metric='CollectionErrors'; Value=$Errors.Count; Interpretation='Feed or NVD request errors' }
)

if (Test-Path -LiteralPath $XlsxPath) { Remove-Item -LiteralPath $XlsxPath -Force }
$Summary | Export-Excel -Path $XlsxPath -WorksheetName 'Summary' -TableName 'SummaryTable' -TableStyle Medium2 -AutoSize -FreezeTopRow -BoldTopRow
$ResultArray | Export-Excel -Path $XlsxPath -WorksheetName 'Assessment' -TableName 'AssessmentTable' -TableStyle Medium2 -AutoSize -FreezeTopRow -BoldTopRow -Append
if ($InvalidLines.Count -gt 0) { $InvalidLines.ToArray() | Export-Excel -Path $XlsxPath -WorksheetName 'Invalid Input' -TableName 'InvalidInputTable' -TableStyle Medium2 -AutoSize -FreezeTopRow -BoldTopRow -Append }
if ($Errors.Count -gt 0) { $Errors.ToArray() | Export-Excel -Path $XlsxPath -WorksheetName 'Errors' -TableName 'ErrorsTable' -TableStyle Medium2 -AutoSize -FreezeTopRow -BoldTopRow -Append }

$Excel = Open-ExcelPackage -Path $XlsxPath
try {
    foreach ($Worksheet in $Excel.Workbook.Worksheets) {
        $Worksheet.View.ShowGridLines = $false
        if ($Worksheet.Dimension) {
            $Worksheet.Row(1).Height = 24
            $Worksheet.Cells[1,1,1,$Worksheet.Dimension.End.Column].Style.Font.Bold = $true
            $Worksheet.Cells[1,1,1,$Worksheet.Dimension.End.Column].Style.Font.Color.SetColor([System.Drawing.Color]::White)
            $Worksheet.Cells[1,1,1,$Worksheet.Dimension.End.Column].Style.Fill.PatternType = 'Solid'
            $Worksheet.Cells[1,1,1,$Worksheet.Dimension.End.Column].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(31,78,121))
            for ($ColumnIndex=1; $ColumnIndex -le $Worksheet.Dimension.End.Column; $ColumnIndex++) {
                $Column = $Worksheet.Column($ColumnIndex)
                if ($Column.Width -gt 60) { $Column.Width = 60 }
                if ($Column.Width -lt 12) { $Column.Width = 12 }
            }
        }
    }
}
finally { if ($null -ne $Excel) { Close-ExcelPackage $Excel } }

$CompletedUtc = [datetime]::UtcNow
Write-Host ''
Write-Pass 'CVE assessment completed.'
Write-Pass "CSV: $CsvPath"
Write-Pass "JSON: $JsonPath"
Write-Pass "Excel: $XlsxPath"
Write-Pass "Feed manifest: $ManifestPath"
Write-Pass "Excel SHA-256: $((Get-FileHash $XlsxPath -Algorithm SHA256).Hash)"
Write-Pass ('Duration: {0:n1} minutes' -f (($CompletedUtc - $StartedUtc).TotalMinutes))
Write-Host ''

$ResultArray | Select-Object `
    CVE,
    CisaKev,
    @{ Name='EPSS %'; Expression={ if ($null -ne $_.EpssProbabilityPercent) { '{0:N2}' -f $_.EpssProbabilityPercent } else { 'N/A' } } },
    @{ Name='EPSS Percentile %'; Expression={ if ($null -ne $_.EpssPercentilePercent) { '{0:N2}' -f $_.EpssPercentilePercent } else { 'N/A' } } },
    CvssBaseScore,
    CvssSeverity,
    ApplicabilityDisposition,
    ContextualPriority |
    Format-Table -AutoSize
