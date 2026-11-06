#requires -Version 7.2
<##
.SYNOPSIS
  Runs repeatable Python security and quality scans against one or more locally cloned repositories.
.VERSION
  1.1.1
##>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Repository,

    [string]$RootPath = 'C:\Tools\PythonSecurity',

    [string]$ScannerEnvironmentName = '.scanner-venv',

    [string]$OutputDirectory,

    [switch]$SkipTests,

    [switch]$SkipArchive
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Version = '1.1.1'
$ReadmePath = Join-Path $PSScriptRoot 'Invoke-PythonRepositorySecurityScan-README.txt'

function Write-ToolBanner {
    $Lines = @(
        ' ____        _   _                 ',
        '|  _ \\ _   _| |_| |__   ___  _ __  ',
        '| |_) | | | | __| ''_ \\ / _ \\| ''_ \\ ',
        '|  __/| |_| | |_| | | | (_) | | | |',
        '|_|    \\__, |\\__|_| |_|\\___/|_| |_|',
        '       |___/  PYTHOOOOON SECURITY SCAN'
    )

    Write-Host ''
    foreach ($Line in $Lines) {
        Write-Host $Line -ForegroundColor Cyan
    }
    Write-Host "       Invoke-PythonRepositorySecurityScan v$Version" -ForegroundColor White
    Write-Host ''
}

function Write-ScanMessage {
    param(
        [ValidateSet('INFO','STEP','PASS','WARN','FAIL')]
        [string]$Level,
        [string]$Message
    )

    $Color = switch ($Level) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        'STEP' { 'Cyan' }
        default { 'White' }
    }

    Write-Host (
        '[{0}] [{1}] {2}' -f (
            Get-Date -Format 'HH:mm:ss'
        ), $Level, $Message
    ) -ForegroundColor $Color
}

function Invoke-NativeEvidenceCommand {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Executable,

        [Parameter(Mandatory)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory)]
        [string]$ConsolePath
    )

    try {
        $Output = & $Executable @ArgumentList 2>&1
        $ExitCode = $LASTEXITCODE

        $Output |
            Out-String |
            Set-Content `
                -LiteralPath $ConsolePath `
                -Encoding utf8

        [pscustomobject]@{
            Tool = $Name
            Executed = $true
            ExitCode = $ExitCode
            Error = $null
            ConsolePath = $ConsolePath
        }
    }
    catch {
        $_.Exception.Message |
            Set-Content `
                -LiteralPath $ConsolePath `
                -Encoding utf8

        [pscustomobject]@{
            Tool = $Name
            Executed = $false
            ExitCode = $null
            Error = $_.Exception.Message
            ConsolePath = $ConsolePath
        }
    }
}

function Get-ToolVersionEvidence {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Executable,

        [Parameter(Mandatory)]
        [string[]]$ArgumentList
    )

    try {
        $Output = & $Executable @ArgumentList 2>&1
        $ExitCode = $LASTEXITCODE

        [pscustomobject]@{
            Tool = $Name
            Available = $ExitCode -eq 0
            ExitCode = $ExitCode
            Version = ($Output | Out-String).Trim()
            Error = $null
        }
    }
    catch {
        [pscustomobject]@{
            Tool = $Name
            Available = $false
            ExitCode = $null
            Version = $null
            Error = $_.Exception.Message
        }
    }
}

Write-ToolBanner
Write-Host 'Make sure you git clone each repository prior to running me.' -ForegroundColor Yellow
Write-Host 'I do Python code scanning only.' -ForegroundColor Yellow
Write-Host ''
Write-ScanMessage INFO "Starting Python repository security scan v$Version"

if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) {
    throw "Root path does not exist: $RootPath"
}

$RootPath = (Resolve-Path -LiteralPath $RootPath).Path
$ScannerEnvironment = Join-Path $RootPath $ScannerEnvironmentName
$ScannerPython = Join-Path $ScannerEnvironment 'Scripts\python.exe'
$SemgrepExecutable = Join-Path $ScannerEnvironment 'Scripts\semgrep.exe'
$SemgrepCacheDirectory = Join-Path $ScannerEnvironment 'cache'
$SemgrepVersionCachePath = Join-Path $SemgrepCacheDirectory 'semgrep_version'

New-Item `
    -ItemType Directory `
    -Path $SemgrepCacheDirectory `
    -Force |
    Out-Null

$env:SEMGREP_VERSION_CACHE_PATH = $SemgrepVersionCachePath

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path `
        $RootPath `
        ('Evidence-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

New-Item `
    -ItemType Directory `
    -Path $OutputDirectory `
    -Force |
    Out-Null

Write-ScanMessage STEP 'Running scanner preflight'
Write-ScanMessage INFO "Semgrep version cache: $SemgrepVersionCachePath"

$ToolVersions = @(
    Get-ToolVersionEvidence `
        -Name 'Python' `
        -Executable $ScannerPython `
        -ArgumentList @('--version')

    Get-ToolVersionEvidence `
        -Name 'Semgrep' `
        -Executable $SemgrepExecutable `
        -ArgumentList @('--version')

    Get-ToolVersionEvidence `
        -Name 'Bandit' `
        -Executable $ScannerPython `
        -ArgumentList @('-m','bandit','--version')

    Get-ToolVersionEvidence `
        -Name 'pip-audit' `
        -Executable $ScannerPython `
        -ArgumentList @('-m','pip_audit','--version')

    Get-ToolVersionEvidence `
        -Name 'Ruff' `
        -Executable $ScannerPython `
        -ArgumentList @('-m','ruff','--version')

    Get-ToolVersionEvidence `
        -Name 'pytest' `
        -Executable $ScannerPython `
        -ArgumentList @('-m','pytest','--version')
)

$ToolVersions |
    ConvertTo-Json -Depth 4 |
    Set-Content `
        -LiteralPath (Join-Path $OutputDirectory 'Tool-Versions.json') `
        -Encoding utf8

$ToolVersions |
    Format-Table Tool, Available, ExitCode, Version -Wrap

$UnavailableTools = @(
    $ToolVersions |
        Where-Object {
            -not $_.Available
        }
)

if ($UnavailableTools.Count -gt 0) {
    $Names = $UnavailableTools.Tool -join ', '
    Write-ScanMessage FAIL "Scanner preflight failed. Unavailable tools: $Names"
    Write-ScanMessage WARN "Refer to $ReadmePath for local scanner-environment setup instructions."
    throw 'Required scanners are unavailable. No repository scan was started.'
}

Write-ScanMessage PASS 'All required scanners passed preflight'

$RepositorySummaries = [Collections.Generic.List[object]]::new()

foreach ($RepositoryName in $Repository) {
    $RepositoryPath = if ([IO.Path]::IsPathRooted($RepositoryName)) {
        $RepositoryName
    }
    else {
        Join-Path $RootPath $RepositoryName
    }

    if (-not (Test-Path -LiteralPath $RepositoryPath -PathType Container)) {
        throw "Repository path does not exist: $RepositoryPath"
    }

    $RepositoryPath = (Resolve-Path -LiteralPath $RepositoryPath).Path
    $ResolvedRepositoryName = Split-Path -Leaf $RepositoryPath
    $EvidencePath = Join-Path $OutputDirectory $ResolvedRepositoryName

    New-Item `
        -ItemType Directory `
        -Path $EvidencePath `
        -Force |
        Out-Null

    Write-Host ''
    Write-ScanMessage STEP "Assessing $ResolvedRepositoryName"

    $GitDirectory = Join-Path $RepositoryPath '.git'

    if (-not (Test-Path -LiteralPath $GitDirectory)) {
        throw "The directory is not a Git clone: $RepositoryPath"
    }

    $WorkingTreeChanges = @(
        git -C $RepositoryPath status --short
    )

    if ($WorkingTreeChanges.Count -gt 0) {
        Write-ScanMessage WARN "Working tree is not clean: $ResolvedRepositoryName"
        Write-ScanMessage WARN 'The scan includes uncommitted changes. Git status and diffs will be preserved as evidence.'
    }

    $WorkingTreeChanges |
        Set-Content `
            -LiteralPath (Join-Path $EvidencePath 'git-status-short.txt') `
            -Encoding utf8

    git -C $RepositoryPath diff --no-ext-diff |
        Set-Content `
            -LiteralPath (Join-Path $EvidencePath 'git-diff-unstaged.patch.txt') `
            -Encoding utf8

    git -C $RepositoryPath diff --cached --no-ext-diff |
        Set-Content `
            -LiteralPath (Join-Path $EvidencePath 'git-diff-staged.patch.txt') `
            -Encoding utf8

    $Branch = (git -C $RepositoryPath branch --show-current | Out-String).Trim()
    $Commit = (git -C $RepositoryPath rev-parse HEAD | Out-String).Trim()
    $Remote = (git -C $RepositoryPath remote get-url origin | Out-String).Trim()

    [pscustomobject]@{
        Repository = $ResolvedRepositoryName
        RepositoryPath = $RepositoryPath
        Remote = $Remote
        Branch = $Branch
        Commit = $Commit
        WorkingTreeClean = $WorkingTreeChanges.Count -eq 0
        ScanStartedUtc = [datetime]::UtcNow.ToString('o')
    } |
        ConvertTo-Json -Depth 4 |
        Set-Content `
            -LiteralPath (Join-Path $EvidencePath 'Repository-Metadata.json') `
            -Encoding utf8

    Write-ScanMessage STEP 'Running Semgrep'

    $SemgrepJson = Join-Path $EvidencePath 'semgrep.json'
    $SemgrepResult = Invoke-NativeEvidenceCommand `
        -Name 'Semgrep' `
        -Executable $SemgrepExecutable `
        -ArgumentList @(
            'scan',
            '--config','auto',
            '--json',
            '--output',$SemgrepJson,
            $RepositoryPath
        ) `
        -ConsolePath (Join-Path $EvidencePath 'semgrep-console.txt')

    Write-ScanMessage STEP 'Running Bandit'

    $BanditJson = Join-Path $EvidencePath 'bandit.json'
    $BanditResult = Invoke-NativeEvidenceCommand `
        -Name 'Bandit' `
        -Executable $ScannerPython `
        -ArgumentList @(
            '-m','bandit',
            '-r',$RepositoryPath,
            '-f','json',
            '-o',$BanditJson
        ) `
        -ConsolePath (Join-Path $EvidencePath 'bandit-console.txt')

    Write-ScanMessage STEP 'Running pip-audit against dependency manifests'

    $RequirementFiles = @(
        Get-ChildItem `
            -LiteralPath $RepositoryPath `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Name.StartsWith('requirements') -and $_.Name.EndsWith('.txt')) -or
            $_.Name -eq 'requirements.lock'
        }
    )

    $PipAuditResults = [Collections.Generic.List[object]]::new()

    foreach ($RequirementFile in $RequirementFiles) {
        $RelativePath = [IO.Path]::GetRelativePath(
            $RepositoryPath,
            $RequirementFile.FullName
        )

        $SafeName = $RelativePath -replace '[\\/:?"<>| ]', '_'
        $PipAuditJson = Join-Path $EvidencePath "pip-audit-$SafeName.json"
        $PipAuditConsole = Join-Path $EvidencePath "pip-audit-$SafeName-console.txt"

        $AuditResult = Invoke-NativeEvidenceCommand `
            -Name "pip-audit: $RelativePath" `
            -Executable $ScannerPython `
            -ArgumentList @(
                '-m','pip_audit',
                '-r',$RequirementFile.FullName,
                '--format','json',
                '--output',$PipAuditJson
            ) `
            -ConsolePath $PipAuditConsole

        $PipAuditResults.Add([pscustomobject]@{
            RequirementFile = $RelativePath
            Executed = $AuditResult.Executed
            ExitCode = $AuditResult.ExitCode
            Error = $AuditResult.Error
            JsonEvidence = $PipAuditJson
            ConsoleEvidence = $PipAuditConsole
        })
    }

    $PipAuditResults |
        ConvertTo-Json -Depth 6 |
        Set-Content `
            -LiteralPath (Join-Path $EvidencePath 'pip-audit-index.json') `
            -Encoding utf8

    Write-ScanMessage STEP 'Running Ruff'

    $RuffResult = Invoke-NativeEvidenceCommand `
        -Name 'Ruff' `
        -Executable $ScannerPython `
        -ArgumentList @(
            '-m','ruff','check',
            $RepositoryPath,
            '--output-format','json'
        ) `
        -ConsolePath (Join-Path $EvidencePath 'ruff.json')

    if ($SkipTests) {
        $PytestResult = [pscustomobject]@{
            Tool = 'pytest'
            Executed = $false
            ExitCode = $null
            Error = 'Skipped by parameter.'
            ConsolePath = $null
        }
    }
    else {
        Write-ScanMessage STEP 'Running pytest'
        $PreviousLocation = Get-Location

        try {
            Set-Location $RepositoryPath

            $PytestResult = Invoke-NativeEvidenceCommand `
                -Name 'pytest' `
                -Executable $ScannerPython `
                -ArgumentList @('-m','pytest','-q') `
                -ConsolePath (Join-Path $EvidencePath 'pytest-results.txt')
        }
        finally {
            Set-Location $PreviousLocation
        }
    }

    $SemgrepFindingCount = $null
    $SemgrepErrorCount = $null
    $BanditFindingCount = $null
    $RuffFindingCount = $null

    if (Test-Path -LiteralPath $SemgrepJson) {
        try {
            $SemgrepData = Get-Content `
                -LiteralPath $SemgrepJson `
                -Raw |
                ConvertFrom-Json

            $SemgrepFindingCount = @($SemgrepData.results).Count
            $SemgrepErrorCount = @($SemgrepData.errors).Count
        }
        catch {
            Write-ScanMessage WARN 'Semgrep JSON could not be summarized'
        }
    }

    if (Test-Path -LiteralPath $BanditJson) {
        try {
            $BanditData = Get-Content `
                -LiteralPath $BanditJson `
                -Raw |
                ConvertFrom-Json

            $BanditFindingCount = @($BanditData.results).Count
        }
        catch {
            Write-ScanMessage WARN 'Bandit JSON could not be summarized'
        }
    }

    if (Test-Path -LiteralPath $RuffResult.ConsolePath) {
        try {
            $RuffData = Get-Content `
                -LiteralPath $RuffResult.ConsolePath `
                -Raw |
                ConvertFrom-Json

            $RuffFindingCount = @($RuffData).Count
        }
        catch {
            Write-ScanMessage WARN 'Ruff JSON could not be summarized'
        }
    }

    $RepositorySummary = [pscustomobject]@{
        Repository = $ResolvedRepositoryName
        Remote = $Remote
        Branch = $Branch
        Commit = $Commit
        WorkingTreeClean = $WorkingTreeChanges.Count -eq 0
        SemgrepExecuted = $SemgrepResult.Executed
        SemgrepExitCode = $SemgrepResult.ExitCode
        SemgrepFindings = $SemgrepFindingCount
        SemgrepErrors = $SemgrepErrorCount
        BanditExecuted = $BanditResult.Executed
        BanditExitCode = $BanditResult.ExitCode
        BanditFindings = $BanditFindingCount
        PipAuditManifestCount = $RequirementFiles.Count
        PipAuditNonzeroCount = @(
            $PipAuditResults |
                Where-Object {
                    $null -ne $_.ExitCode -and $_.ExitCode -ne 0
                }
        ).Count
        RuffExecuted = $RuffResult.Executed
        RuffExitCode = $RuffResult.ExitCode
        RuffFindings = $RuffFindingCount
        PytestExecuted = $PytestResult.Executed
        PytestExitCode = $PytestResult.ExitCode
        EvidencePath = $EvidencePath
        ScanCompletedUtc = [datetime]::UtcNow.ToString('o')
    }

    $RepositorySummary |
        ConvertTo-Json -Depth 6 |
        Set-Content `
            -LiteralPath (Join-Path $EvidencePath 'Scan-Summary.json') `
            -Encoding utf8

    $RepositorySummaries.Add($RepositorySummary)
    Write-ScanMessage PASS "Completed $ResolvedRepositoryName"
}

$RepositorySummaries |
    Export-Csv `
        -LiteralPath (Join-Path $OutputDirectory 'Scanner-Result-Summary.csv') `
        -NoTypeInformation `
        -Encoding utf8

$RepositorySummaries |
    ConvertTo-Json -Depth 6 |
    Set-Content `
        -LiteralPath (Join-Path $OutputDirectory 'Scanner-Result-Summary.json') `
        -Encoding utf8

Write-Host ''
$RepositorySummaries |
    Format-Table `
        Repository,
        SemgrepFindings,
        BanditFindings,
        PipAuditNonzeroCount,
        RuffFindings,
        PytestExitCode `
        -AutoSize

if (-not $SkipArchive) {
    $ArchivePath = "$OutputDirectory.zip"
    Remove-Item `
        -LiteralPath $ArchivePath `
        -Force `
        -ErrorAction SilentlyContinue

    Compress-Archive `
        -LiteralPath $OutputDirectory `
        -DestinationPath $ArchivePath `
        -CompressionLevel Optimal

    $Hash = Get-FileHash `
        -LiteralPath $ArchivePath `
        -Algorithm SHA256

    Write-ScanMessage PASS "Evidence archive: $ArchivePath"
    Write-ScanMessage INFO "SHA256: $($Hash.Hash)"
}

Write-ScanMessage PASS "Assessment complete: $OutputDirectory"
