Invoke-PythonRepositorySecurityScan
Version 1.1.1

PURPOSE

Invoke-PythonRepositorySecurityScan.ps1 runs repeatable Python repository scans with:

- Semgrep Community Edition
- Bandit
- pip-audit
- Ruff
- pytest

The script is read-only against source files. It writes evidence to a separate timestamped directory and optionally creates a ZIP archive.

SUPPORTED ENVIRONMENT

- Windows 10 or Windows 11
- PowerShell 7.2 or newer
- Git for Windows
- Python 3.10 or newer
- Local Git clones under C:\Tools\PythonSecurity by default

The scanner environment is expected at:

C:\Tools\PythonSecurity\.scanner-venv

The script does not install or update scanner packages automatically. This prevents unplanned changes during an assessment.

ONE-TIME SCANNER ENVIRONMENT SETUP

if C:\Tools\PythonSecurity\.scanner-venv exists no need to run this again!

Open PowerShell 7 and run:

Set-Location 'C:\Tools\PythonSecurity'

python -m venv '.scanner-venv'

$ScannerPython = Join-Path `
    $PWD `
    '.scanner-venv\Scripts\python.exe'

& $ScannerPython -m pip install `
    --upgrade `
    pip `
    setuptools `
    wheel

& $ScannerPython -m pip install `
    semgrep `
    bandit `
    pip-audit `
    ruff `
    pytest

VERIFY THE SCANNER ENVIRONMENT

Run:

$ScannerPython = 'C:\Tools\PythonSecurity\.scanner-venv\Scripts\python.exe'
$Semgrep = 'C:\Tools\PythonSecurity\.scanner-venv\Scripts\semgrep.exe'

& $ScannerPython --version
& $Semgrep --version
& $ScannerPython -m bandit --version
& $ScannerPython -m pip_audit --version
& $ScannerPython -m ruff --version
& $ScannerPython -m pytest --version

Every command must return a version and exit successfully. The scan script repeats this preflight before scanning any repository.

SEMGREP CACHE HANDLING

Semgrep performs a version check and writes a small cache file. Some Windows profiles may have a non-writable default cache path, which can produce an error similar to:

Permission denied: C:\Users\username\.cache\semgrep_version

Version 1.1.1 handles this automatically. Before the preflight and scan, the script creates and uses this writable cache path inside the scanner environment:

C:\Tools\PythonSecurity\.scanner-venv\cache\semgrep_version

The script sets SEMGREP_VERSION_CACHE_PATH only for the current PowerShell process and child scanner processes. No manual cache repair or profile permission change is required.

CLONE A REPOSITORY

Clone each repository before running the scanner:

Set-Location 'C:\Tools\PythonSecurity'

git clone https://github.com/example/example-python-repository.git

The resulting local directory would normally be:

C:\Tools\PythonSecurity\example-python-repository

RUN ONE REPOSITORY SCAN

Set-Location 'C:\Tools\PythonSecurity'

.\Invoke-PythonRepositorySecurityScan.ps1 `
    -Repository 'example-python-repository'

RUN MULTIPLE REPOSITORY SCANS

.\Invoke-PythonRepositorySecurityScan.ps1 `
    -Repository `
        'repository-one', `
        'repository-two'

The script also accepts absolute repository paths.

OUTPUT

Each run creates a timestamped evidence directory similar to:

C:\Tools\PythonSecurity\Evidence-20261106-111517

The evidence includes:

- Scanner versions
- Git remote, branch, commit, and working-tree state
- Git status and staged or unstaged diffs when present
- Semgrep JSON and console output
- Bandit JSON and console output
- pip-audit JSON and console output for every supported requirements manifest
- Ruff JSON
- pytest output
- Per-repository JSON summary
- Combined CSV and JSON summary
- ZIP archive unless SkipArchive is specified

IMPORTANT WORKING-TREE NOTE

A clean Git working tree is preferred. If uncommitted changes exist, the script warns that the scan includes those changes and saves Git status and diff evidence. The commit hash alone does not fully identify a dirty working tree.

COMMON PARAMETERS

Skip pytest:

.\Invoke-PythonRepositorySecurityScan.ps1 `
    -Repository 'example-python-repository' `
    -SkipTests

Skip ZIP creation:

.\Invoke-PythonRepositorySecurityScan.ps1 `
    -Repository 'example-python-repository' `
    -SkipArchive

Use another clone root:

.\Invoke-PythonRepositorySecurityScan.ps1 `
    -RootPath 'D:\Security\PythonRepositories' `
    -Repository 'example-python-repository'

INTERPRETING EXIT CODES

- Semgrep zero normally means the scan completed. Read semgrep.json for findings and errors.
- Bandit one normally means findings were reported.
- pip-audit zero means no known vulnerable dependency was reported for that manifest.
- Ruff one normally means lint findings were reported.
- pytest zero means tests passed.
- pytest three indicates an internal or collection error.
- pytest five means no tests were collected.

A scanner finding is an evidence lead, not automatically a confirmed vulnerability. Review source context, data flow, reachability, configuration, and compensating controls before opening remediation work.

UPDATING THE SCANNERS

Scanner upgrades can change rules and results. Record versions before and after any update.

$ScannerPython = 'C:\Tools\PythonSecurity\.scanner-venv\Scripts\python.exe'

& $ScannerPython -m pip install `
    --upgrade `
    semgrep `
    bandit `
    pip-audit `
    ruff `
    pytest

PUBLIC REPOSITORY NOTE

The script contains no organization-specific repository names, domains, credentials, or tokens. Do not commit generated evidence, proprietary source, local paths containing personal information, or scanner archives to a public repository.
