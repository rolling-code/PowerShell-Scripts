<#
.SYNOPSIS
Checks prerequisites and prepares or starts a local ARTEX deployment backed by Ollama.
.DESCRIPTION
Performs a clear, non-debugging readiness check for Docker Desktop and Ollama, reports exact
versions and installation guidance when a prerequisite is unavailable, optionally clones ARTEX
into the configured repository path, writes the local ARTEX configuration, starts the Docker
Compose deployment, and reports repository, model, container, and listener versions/status.
Safe to rerun when ARTEX is already cloned and running.
Version: 1.1.0
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $RepositoryPath = 'C:\Tools\ARTEX',

    [Parameter()]
    [string] $RepositoryUrl = 'https://github.com/BaaRai/ARTEX.git',

    [Parameter()]
    [string] $Branch = 'main',

    [Parameter()]
    [string] $OllamaModel = 'hf.co/unsloth/Qwen3.5-9B-GGUF:Q4_K_M',

    [Parameter()]
    [string] $OllamaHostUrl = 'http://127.0.0.1:11434',

    [Parameter()]
    [string] $OllamaContainerBaseUrl = 'http://host.docker.internal:11434/v1',

    [Parameter()]
    [string] $ArtexUrl = 'http://127.0.0.1:8787',

    [Parameter()]
    [switch] $SkipGitUpdate,

    [Parameter()]
    [switch] $SkipBuild,

    [Parameter()]
    [switch] $OpenBrowser,

    [Parameter()]
    [switch] $ConfirmClone
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$DockerInstallUrl = 'https://docs.docker.com/desktop/setup/install/windows-install/'
$OllamaInstallUrl = 'https://ollama.com/download/windows'
$GitInstallUrl = 'https://git-scm.com/install/windows'

function Write-Step { param([string] $Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Pass { param([string] $Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-WarnText { param([string] $Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Fail { param([string] $Message) Write-Host "[-] $Message" -ForegroundColor Red }

function Invoke-Native {
    param(
        [Parameter(Mandatory)][string] $Command,
        [Parameter(Mandatory)][string[]] $Arguments,
        [switch] $Capture
    )

    if ($Capture) {
        $output = @(& $Command @Arguments 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "$Command $($Arguments -join ' ') failed:`n$($output -join "`n")"
        }
        return $output
    }

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function New-RandomSecret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($bytes).Replace('+', 'A').Replace('/', 'B').TrimEnd('=')
}

function Stop-NotReady {
    param(
        [Parameter(Mandatory)][string] $Component,
        [Parameter(Mandatory)][string] $Reason,
        [Parameter(Mandatory)][string] $InstallUrl
    )

    Write-Fail "$Component is not ready."
    Write-Host "Reason: $Reason" -ForegroundColor Yellow
    Write-Host "Install or repair $Component using: $InstallUrl" -ForegroundColor Yellow
    throw "$Component readiness check failed. No debugging or automatic prerequisite installation was attempted."
}

Write-Host ''
Write-Host 'ARTEX local setup and readiness check v1.1.0' -ForegroundColor White
Write-Host "Expected ARTEX repository location: $RepositoryPath" -ForegroundColor Gray
Write-Host "ARTEX repository source: $RepositoryUrl" -ForegroundColor Gray
Write-Host "Requested branch: $Branch" -ForegroundColor Gray
Write-Host "Requested Ollama model: $OllamaModel" -ForegroundColor Gray
Write-Host ''

Write-Step 'Checking whether Docker is installed via Get-Command docker'
$dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCommand) {
    Stop-NotReady -Component 'Docker Desktop' -Reason 'The docker command was not found in PATH.' -InstallUrl $DockerInstallUrl
}

$dockerClientVersion = (& docker version --format '{{.Client.Version}}' 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($dockerClientVersion)) {
    Stop-NotReady -Component 'Docker Desktop' -Reason 'The Docker CLI is installed, but its client version could not be read.' -InstallUrl $DockerInstallUrl
}
Write-Pass "Docker CLI found at $($dockerCommand.Source); client version=$dockerClientVersion"

Write-Step 'Checking whether the Docker Linux engine is running via docker version'
$dockerServerVersion = (& docker version --format '{{.Server.Version}}' 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($dockerServerVersion)) {
    Stop-NotReady -Component 'Docker Desktop' -Reason 'The Docker CLI is installed, but the Docker engine is not responding. Start Docker Desktop and wait until the engine reports ready.' -InstallUrl $DockerInstallUrl
}

$dockerContext = (& docker context show 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($dockerContext)) {
    Stop-NotReady -Component 'Docker Desktop' -Reason 'Docker is responding, but the active context could not be determined.' -InstallUrl $DockerInstallUrl
}

$dockerComposeVersion = (& docker compose version --short 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($dockerComposeVersion)) {
    Stop-NotReady -Component 'Docker Compose' -Reason 'docker compose is unavailable even though Docker is installed.' -InstallUrl $DockerInstallUrl
}
Write-Pass "Docker ready; server=$dockerServerVersion; context=$dockerContext; compose=$dockerComposeVersion"

Write-Step 'Checking whether Ollama is installed via Get-Command ollama'
$ollamaCommand = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollamaCommand) {
    Stop-NotReady -Component 'Ollama' -Reason 'The ollama command was not found in PATH.' -InstallUrl $OllamaInstallUrl
}

$ollamaVersion = (& ollama --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ollamaVersion)) {
    Stop-NotReady -Component 'Ollama' -Reason 'The Ollama executable exists, but its version could not be read.' -InstallUrl $OllamaInstallUrl
}
Write-Pass "Ollama found at $($ollamaCommand.Source); version=$ollamaVersion"

Write-Step "Checking whether the Ollama API is ready at $OllamaHostUrl"
try {
    $tags = Invoke-RestMethod -Method Get -Uri "$OllamaHostUrl/api/tags" -TimeoutSec 15
}
catch {
    Stop-NotReady -Component 'Ollama' -Reason "The Ollama API is not responding at $OllamaHostUrl. Start Ollama and retry. $($_.Exception.Message)" -InstallUrl $OllamaInstallUrl
}

$availableModels = @($tags.models | ForEach-Object { [string] $_.name })
if ($OllamaModel -notin $availableModels) {
    Write-Fail "The requested model is not installed: $OllamaModel"
    Write-Host "Installed models: $($availableModels -join ', ')" -ForegroundColor Yellow
    Write-Host "Install it with: ollama pull `"$OllamaModel`"" -ForegroundColor Yellow
    throw 'Ollama is running, but the requested LLM is not ready.'
}
Write-Pass "Ollama API ready; selected LLM=$OllamaModel"

if (-not (Test-Path -LiteralPath $RepositoryPath -PathType Container)) {
    Write-WarnText "ARTEX is not present at the expected hard-coded default location: $RepositoryPath"
    Write-Host "ARTEX will be installed there using git clone from $RepositoryUrl." -ForegroundColor Yellow

    $cloneApproved = $ConfirmClone.IsPresent
    if (-not $cloneApproved) {
        $answer = Read-Host "Clone ARTEX into '$RepositoryPath'? [Y]es or [N]o"
        $cloneApproved = $answer -match '^(?i:y|yes)$'
    }

    if (-not $cloneApproved) {
        throw 'ARTEX clone was declined. No repository changes were made.'
    }

    Write-Step 'Checking whether Git is installed because cloning is required'
    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCommand) {
        Write-Fail 'Git is required only because ARTEX is not yet cloned.'
        Write-Host "Install Git for Windows using: $GitInstallUrl" -ForegroundColor Yellow
        throw 'Git is unavailable; ARTEX could not be cloned.'
    }

    $gitVersion = (& git --version 2>&1 | Out-String).Trim()
    Write-Pass "Git ready at $($gitCommand.Source); version=$gitVersion"
    Write-Step "Installing ARTEX at $RepositoryPath via git clone"

    $parent = Split-Path -Parent $RepositoryPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Invoke-Native -Command 'git' -Arguments @('clone', '--branch', $Branch, '--single-branch', $RepositoryUrl, $RepositoryPath)
}
else {
    Write-Pass "Existing ARTEX directory detected at $RepositoryPath; git clone is not required"
}

if (-not (Test-Path -LiteralPath (Join-Path $RepositoryPath '.git') -PathType Container)) {
    throw "The expected path exists but is not a Git repository: $RepositoryPath"
}

$gitCommandExisting = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCommandExisting) {
    Write-Fail 'Git is required to identify and optionally update the existing ARTEX repository.'
    Write-Host "Install Git for Windows using: $GitInstallUrl" -ForegroundColor Yellow
    throw 'Git is unavailable.'
}
$gitVersionExisting = (& git --version 2>&1 | Out-String).Trim()
Write-Pass "Using Git version: $gitVersionExisting"

Push-Location $RepositoryPath
try {
    foreach ($requiredFile in @('docker-compose.yml', 'Dockerfile', '.env.example')) {
        if (-not (Test-Path -LiteralPath (Join-Path $RepositoryPath $requiredFile) -PathType Leaf)) {
            throw "Required ARTEX repository file is missing: $requiredFile"
        }
    }

    $origin = ((Invoke-Native -Command 'git' -Arguments @('remote', 'get-url', 'origin') -Capture) -join '').Trim()
    $currentBranch = ((Invoke-Native -Command 'git' -Arguments @('branch', '--show-current') -Capture) -join '').Trim()
    $workingTree = @(Invoke-Native -Command 'git' -Arguments @('status', '--porcelain=v1') -Capture)

    Write-Pass "ARTEX repository origin=$origin"
    Write-Pass "ARTEX repository branch=$currentBranch"

    if ($origin -ne $RepositoryUrl) {
        throw "Unexpected ARTEX origin. Expected '$RepositoryUrl'; found '$origin'."
    }
    if ($currentBranch -ne $Branch) {
        throw "Unexpected ARTEX branch. Expected '$Branch'; found '$currentBranch'."
    }

    if ($workingTree.Count -gt 0) {
        Write-WarnText 'ARTEX working tree contains local changes; automatic update will be skipped.'
    }
    elseif (-not $SkipGitUpdate) {
        Write-Step 'Updating the existing ARTEX repository using fast-forward only'
        Invoke-Native -Command 'git' -Arguments @('fetch', '--prune', 'origin')
        Invoke-Native -Command 'git' -Arguments @('pull', '--ff-only', 'origin', $Branch)
    }
    else {
        Write-Step 'Skipping ARTEX repository update because -SkipGitUpdate was specified'
    }

    $commit = ((Invoke-Native -Command 'git' -Arguments @('rev-parse', 'HEAD') -Capture) -join '').Trim()
    $commitDate = ((Invoke-Native -Command 'git' -Arguments @('show', '-s', '--format=%cI', 'HEAD') -Capture) -join '').Trim()
    Write-Pass "ARTEX source ready; commit=$commit; commit date=$commitDate"

    $envPath = Join-Path $RepositoryPath '.env'
    $password = $null
    if (Test-Path -LiteralPath $envPath -PathType Leaf) {
        $passwordLine = Get-Content -LiteralPath $envPath | Where-Object { $_ -match '^POSTGRES_PASSWORD=' } | Select-Object -First 1
        if ($passwordLine) {
            $password = ($passwordLine -split '=', 2)[1]
        }
    }
    if ([string]::IsNullOrWhiteSpace($password) -or $password -eq 'change-me-please') {
        $password = New-RandomSecret
    }

    $envContent = @"
ARTEX_BIND_ADDR=127.0.0.1
ARTEX_TRUSTED_PROXIES=
POSTGRES_USER=artex
POSTGRES_PASSWORD=$password
POSTGRES_DB=artex
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
ARTEX_LLM_PROVIDER=ollama
ARTEX_LLM_MODEL=$OllamaModel
ARTEX_LLM_BASE_URL=$OllamaContainerBaseUrl
ARTEX_LLM_PROXY=
ARTEX_UNTRUSTED_BOUNDARY=1
ARTEX_UPDATE_CHECK=0
"@
    [IO.File]::WriteAllText($envPath, ($envContent -replace "`r`n", "`n"), [Text.UTF8Encoding]::new($false))
    Write-Pass "ARTEX configuration ready at $envPath; provider=ollama; model=$OllamaModel"

    if (-not $SkipBuild) {
        Write-Step "Building ARTEX commit $commit with Docker $dockerServerVersion"
        Invoke-Native -Command 'docker' -Arguments @('compose', 'build', '--pull')
    }
    else {
        Write-Step 'Skipping image build because -SkipBuild was specified'
    }

    $runningServices = @(& docker compose ps --services --filter status=running 2>$null)
    if ('artex' -in $runningServices -and 'postgres' -in $runningServices) {
        Write-Pass 'ARTEX and PostgreSQL are already running; preserving the existing deployment'
    }
    else {
        Write-Step 'Starting ARTEX and PostgreSQL with docker compose up -d'
        Invoke-Native -Command 'docker' -Arguments @('compose', 'up', '-d')
    }

    Write-Step 'Checking ARTEX container and image versions'
    Invoke-Native -Command 'docker' -Arguments @('compose', 'ps')
    $composeImages = @(& docker compose images 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $composeImages | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
    }

    Write-Step "Waiting for the ARTEX web interface at $ArtexUrl"
    $ready = $false
    foreach ($attempt in 1..36) {
        try {
            $response = Invoke-WebRequest -Uri $ArtexUrl -Method Get -TimeoutSec 5 -UseBasicParsing
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                $ready = $true
                break
            }
        }
        catch {
            Start-Sleep -Seconds 5
        }
    }
    if (-not $ready) {
        throw "ARTEX did not become reachable at $ArtexUrl within three minutes. Review Docker Desktop and ARTEX container logs manually."
    }

    Write-Pass "ARTEX is ready at $ArtexUrl"
    Write-Host ''
    Write-Host 'Version summary' -ForegroundColor White
    Write-Host "  Setup script: 1.1.0" -ForegroundColor Gray
    Write-Host "  Git: $gitVersionExisting" -ForegroundColor Gray
    Write-Host "  Docker client: $dockerClientVersion" -ForegroundColor Gray
    Write-Host "  Docker server: $dockerServerVersion" -ForegroundColor Gray
    Write-Host "  Docker Compose: $dockerComposeVersion" -ForegroundColor Gray
    Write-Host "  Docker context: $dockerContext" -ForegroundColor Gray
    Write-Host "  Ollama: $ollamaVersion" -ForegroundColor Gray
    Write-Host "  Ollama model: $OllamaModel" -ForegroundColor Gray
    Write-Host "  ARTEX repository: $RepositoryPath" -ForegroundColor Gray
    Write-Host "  ARTEX branch: $currentBranch" -ForegroundColor Gray
    Write-Host "  ARTEX commit: $commit" -ForegroundColor Gray
    Write-Host "  ARTEX URL: $ArtexUrl" -ForegroundColor Gray

    if ($OpenBrowser) {
        Start-Process $ArtexUrl
    }
}
finally {
    Pop-Location
}
