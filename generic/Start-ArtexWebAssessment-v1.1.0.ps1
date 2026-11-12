<#
.SYNOPSIS
Creates a generic first-run ARTEX web-assessment campaign package.
.DESCRIPTION
Validates a user-supplied HTTPS origin, confirms the local ARTEX deployment, creates a durable
campaign folder and generic prompt, copies the prompt to the clipboard, opens ARTEX locally,
and prints Microsoft Edge extension installation steps. No organization-specific names,
targets, profiles, or reusable credentials are embedded.
Version: 1.1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [Alias('Url', 'TargetUrl')]
    [ValidatePattern('^https://')]
    [string] $Domain,

    [Parameter()]
    [string] $RepositoryPath = 'C:\Tools\ARTEX',

    [Parameter()]
    [string] $ArtexUrl = 'http://127.0.0.1:8787',

    [Parameter()]
    [string] $CampaignRoot = 'C:\Tools\ARTEX-Campaigns',

    [Parameter()]
    [ValidateSet('FirstRun', 'Baseline')]
    [string] $Profile = 'FirstRun',

    [Parameter()]
    [switch] $OpenBrowser = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step { param([string] $Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Pass { param([string] $Message) Write-Host "[+] $Message" -ForegroundColor Green }

Write-Host ''
Write-Host 'ARTEX first-run web assessment launcher v1.1.0' -ForegroundColor White
Write-Host "Expected ARTEX repository: $RepositoryPath" -ForegroundColor Gray
Write-Host "Campaign data root: $CampaignRoot" -ForegroundColor Gray
Write-Host "Requested target: $Domain" -ForegroundColor Gray
Write-Host "Campaign profile: $Profile" -ForegroundColor Gray
Write-Host ''

Write-Step 'Running ARTEX web-assessment preflight'
foreach ($command in @('docker', 'git', 'ollama')) {
    $resolved = Get-Command $command -ErrorAction SilentlyContinue
    if (-not $resolved) {
        throw "Required command is unavailable: $command. Run Check-ArtexSetup-v1.1.0.ps1 first."
    }
    $versionText = switch ($command) {
        'docker' { (& docker --version 2>&1 | Out-String).Trim() }
        'git' { (& git --version 2>&1 | Out-String).Trim() }
        'ollama' { (& ollama --version 2>&1 | Out-String).Trim() }
    }
    Write-Pass "$command ready at $($resolved.Source); version=$versionText"
}

if (-not (Test-Path -LiteralPath $RepositoryPath -PathType Container)) {
    throw "ARTEX repository was not found at $RepositoryPath. Run Check-ArtexSetup-v1.1.0.ps1 first."
}

try {
    $targetUri = [Uri] $Domain
}
catch {
    throw "Invalid target URL: $Domain"
}
if ($targetUri.Scheme -ne 'https') {
    throw 'Only HTTPS targets are accepted by this first-run launcher.'
}
if (-not [string]::IsNullOrWhiteSpace($targetUri.UserInfo)) {
    throw 'Do not include credentials in the target URL.'
}
if (-not [string]::IsNullOrWhiteSpace($targetUri.Query) -or -not [string]::IsNullOrWhiteSpace($targetUri.Fragment)) {
    throw 'Provide an origin URL without query parameters or fragments.'
}
if ($targetUri.AbsolutePath -ne '/') {
    throw 'Provide only the HTTPS origin, for example https://app.example.test, without an application path.'
}

$origin = $targetUri.GetLeftPart([UriPartial]::Authority)
$hostName = $targetUri.DnsSafeHost

Push-Location $RepositoryPath
try {
    $serverVersion = (& docker version --format '{{.Server.Version}}' 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($serverVersion)) {
        throw 'Docker Desktop Linux engine is unavailable. Run Check-ArtexSetup-v1.1.0.ps1 first.'
    }

    $composeVersion = (& docker compose version --short 2>&1 | Out-String).Trim()
    $services = @(& docker compose ps --services --filter status=running 2>&1)
    if ($LASTEXITCODE -ne 0 -or 'artex' -notin $services -or 'postgres' -notin $services) {
        throw 'ARTEX and PostgreSQL are not both running. Run Check-ArtexSetup-v1.1.0.ps1 first.'
    }

    $branch = (& git branch --show-current 2>&1 | Out-String).Trim()
    $commit = (& git rev-parse HEAD 2>&1 | Out-String).Trim()
    Write-Pass "ARTEX deployment ready; Docker=$serverVersion; Compose=$composeVersion; branch=$branch; commit=$commit"
}
finally {
    Pop-Location
}

try {
    $ollamaVersion = (& ollama --version 2>&1 | Out-String).Trim()
    $ollamaTags = Invoke-RestMethod -Method Get -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 15
    $models = @($ollamaTags.models | ForEach-Object { [string] $_.name })
    Write-Pass "Ollama ready; version=$ollamaVersion; installed models=$($models -join ', ')"
}
catch {
    throw "Ollama readiness check failed. Run Check-ArtexSetup-v1.1.0.ps1 first. $($_.Exception.Message)"
}

try {
    $localResponse = Invoke-WebRequest -Uri $ArtexUrl -UseBasicParsing -TimeoutSec 10
    if ($localResponse.StatusCode -lt 200 -or $localResponse.StatusCode -ge 500) {
        throw "Unexpected ARTEX status code: $($localResponse.StatusCode)"
    }
}
catch {
    throw "ARTEX is not reachable at $ArtexUrl. $($_.Exception.Message)"
}
Write-Pass "ARTEX web interface reachable at $ArtexUrl"

Write-Step "Validating target DNS resolution and HTTPS reachability: $origin"
try {
    $dns = Resolve-DnsName -Name $hostName -Type A -ErrorAction Stop
    $addresses = @($dns | Where-Object IPAddress | ForEach-Object IPAddress)
    if ($addresses.Count -eq 0) {
        throw 'No IPv4 address was returned.'
    }
}
catch {
    throw "DNS resolution failed for $hostName. $($_.Exception.Message)"
}

try {
    $targetResponse = Invoke-WebRequest -Uri $origin -Method Head -MaximumRedirection 5 -UseBasicParsing -TimeoutSec 20
    $statusCode = $targetResponse.StatusCode
}
catch {
    if ($_.Exception.Response) {
        $statusCode = [int] $_.Exception.Response.StatusCode
    }
    else {
        throw "HTTPS reachability check failed for $origin. $($_.Exception.Message)"
    }
}
Write-Pass "Target reachable; HTTP status=$statusCode; addresses=$($addresses -join ', ')"

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$safeHost = $hostName -replace '[^a-zA-Z0-9.-]', '_'
$campaignPath = Join-Path $CampaignRoot "$timestamp-$safeHost-$Profile"
New-Item -ItemType Directory -Path $campaignPath -Force | Out-Null

$objective = if ($Profile -eq 'FirstRun') {
@'
Perform a practical first-run assessment of the exact authorized web origin. Map reachable routes, technologies, authentication boundaries, inputs, upload surfaces, security headers, session behavior, and evidence-supported weaknesses. Prioritize tests that demonstrate ARTEX capabilities while keeping requests scoped to the supplied origin and recording reproducible evidence.
'@
}
else {
@'
Perform a web-application baseline assessment of the exact authorized origin. Identify reachable routes, technologies, authentication boundaries, input surfaces, security headers, session behavior, and evidence-supported weaknesses. Record reproducible request and response evidence for material observations.
'@
}

$prompt = @"
Campaign name: ARTEX POC - $hostName - $Profile - $timestamp

AUTHORIZED TARGET
- Exact origin: $origin
- Exact permitted hostname: $hostName
- Environment: operator-authorized non-production test environment
- Keep active testing on the exact hostname supplied by the operator. Record redirects or third-party dependencies separately rather than silently expanding scope.

OBJECTIVE
$($objective.Trim())

ASSESSMENT ACTIVITIES
- Navigate and map the exact web application hostname.
- Record HTTP status codes, redirects, response headers, cookies, forms, APIs, and application routes.
- Use an authenticated browser session after the operator establishes it through the normal application login flow.
- Exercise representative inputs, API operations, and upload features available to the authenticated test account.
- Evaluate server-side validation, authorization boundaries, session handling, storage behavior, retrieval behavior, error handling, and security controls.
- Capture reproducible request and response evidence with exact timestamps.
- Avoid displaying complete session cookies, bearer tokens, passwords, or other reusable credentials in findings or reports. Use redacted fingerprints when credential correlation is required.

EVIDENCE STANDARD
- Distinguish Confirmed, Likely, Inconclusive, Not detected, and Not applicable.
- A finding requires a reproducible request and response demonstrating the central behavior.
- Record what control was bypassed, what remained enforced, and what was not tested.
- Do not infer impact beyond the captured evidence.

EXPECTED OUTPUT
1. Executive summary.
2. Exact tested scope.
3. Test matrix with each test, result, and evidence reference.
4. Confirmed findings with reproducible steps.
5. Controls that operated correctly.
6. Unknowns and shortest next validation.
"@

$promptPath = Join-Path $campaignPath 'ARTEX-Campaign-Prompt.txt'
$metadataPath = Join-Path $campaignPath 'Campaign-Metadata.json'
[IO.File]::WriteAllText($promptPath, ($prompt -replace "`r`n", "`n"), [Text.UTF8Encoding]::new($false))

$metadata = [ordered]@{
    ScriptVersion = '1.1.0'
    CreatedAt = (Get-Date).ToString('o')
    Profile = $Profile
    Origin = $origin
    Hostname = $hostName
    ResolvedAddresses = $addresses
    PreflightHttpStatus = $statusCode
    ArtexUrl = $ArtexUrl
    RepositoryPath = $RepositoryPath
    CampaignPath = $campaignPath
    PromptPath = $promptPath
}
$metadataJson = $metadata | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($metadataPath, ($metadataJson -replace "`r`n", "`n"), [Text.UTF8Encoding]::new($false))

Set-Clipboard -Value $prompt
Write-Pass "Campaign package created: $campaignPath"
Write-Pass "Campaign prompt saved: $promptPath"
Write-Pass "Campaign metadata saved: $metadataPath"
Write-Pass 'Campaign prompt copied to the clipboard'

Write-Host ''
Write-Host 'Microsoft Edge extension setup:' -ForegroundColor Yellow
Write-Host '1. Open edge://extensions in Microsoft Edge.'
Write-Host '2. Enable Developer mode.'
Write-Host '3. Choose Load unpacked.'
Write-Host '4. Select the ARTEX browser-extension folder from the local ARTEX repository.'
Write-Host '5. Open the ARTEX Traffic Capture extension details.'
Write-Host "6. Under Site access, choose On specific sites and add: $origin/*"
Write-Host '7. Pin the extension, open the target application, and use the normal login flow if authentication is required.'
Write-Host ''
Write-Host 'In ARTEX:' -ForegroundColor Yellow
Write-Host '1. Create a new campaign or task.'
Write-Host '2. Paste the campaign prompt from the clipboard.'
Write-Host '3. Start with agent concurrency at 1 and increase it only after confirming visible request/response evidence.'
Write-Host "4. Save exports and evidence under: $campaignPath"
Write-Host "5. ARTEX campaign data root: $CampaignRoot"

if ($OpenBrowser) {
    Start-Process $ArtexUrl
}
