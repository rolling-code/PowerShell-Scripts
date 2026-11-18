#requires -Version 5.1
<#
.SYNOPSIS
    Installs, updates, and imports Mario's frequently used PowerShell modules.

.DESCRIPTION
    A reusable Windows PowerShell 5.1 / PowerShell 7 preflight that:
      - Reports the current PowerShell environment.
      - Bootstraps PSGallery, NuGet, PackageManagement, and PowerShellGet safely.
      - Installs missing Windows RSAT capabilities when running elevated.
      - Installs missing modules before attempting updates.
      - Updates only the explicitly managed module set.
      - Imports modules after update operations to avoid in-use update conflicts.
      - Uses side-by-side Install-Module updates even for modules not registered by PowerShellGet.
      - Reports persisted Az context explicitly without changing authentication state.
      - Loads PSReflect and PowerView only in Windows PowerShell 5.1.
      - Configures the Azure CLI Automation extension only when az is installed.

    Errors are reported per operation and do not stop unrelated preflight work.

.VERSION
    2.0.0
#>

[CmdletBinding()]
param(
    [ValidateSet('Prompt', 'Always', 'Never')]
    [string]$UpdateMode = 'Prompt',

    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$ModuleScope = 'CurrentUser',

    [string]$ToolRoot = $PSScriptRoot,

    [switch]$SkipWindowsCapabilities,

    [switch]$SkipAzureCliConfiguration,

    [switch]$SetCurrentUserExecutionPolicy,

    [string]$ExpectedAzAccount
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$ScriptVersion = '2.1.0'
$PowerShellVersion = $PSVersionTable.PSVersion
$IsWindowsPlatform = if (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
    [bool]$IsWindows
}
else {
    $env:OS -eq 'Windows_NT'
}

if ([string]::IsNullOrWhiteSpace($ToolRoot)) {
    $ToolRoot = (Get-Location).Path
}

$ManagedModules = @(
    [pscustomobject]@{ Name = 'Microsoft.Entra'; Scope = $ModuleScope; AllowClobber = $true; Import = $false },
    [pscustomobject]@{ Name = 'AADInternals'; Scope = $ModuleScope; AllowClobber = $true; Import = $true },
    [pscustomobject]@{ Name = 'AADInternals-Endpoints'; Scope = $ModuleScope; AllowClobber = $true; Import = $true },
    [pscustomobject]@{ Name = 'Az'; Scope = $ModuleScope; AllowClobber = $true; Import = $false },
    [pscustomobject]@{ Name = 'DSInternals'; Scope = $ModuleScope; AllowClobber = $true; Import = $true },
    [pscustomobject]@{ Name = 'PSPreworkout'; Scope = $ModuleScope; AllowClobber = $true; Import = $true }
)

$Results = New-Object System.Collections.Generic.List[object]

function Write-Stage {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')][string]$Level = 'Info'
    )

    $Color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        default   { 'Cyan' }
    }

    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor $Color
}

function Add-Result {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Status,
        [string]$Detail
    )

    $Results.Add([pscustomobject]@{
        Timestamp = Get-Date
        Category = $Category
        Name = $Name
        Status = $Status
        Detail = $Detail
    })
}

function Test-IsAdministrator {
    if (-not $IsWindowsPlatform) {
        return $false
    }

    try {
        $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
        return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Invoke-SafeOperation {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$OperationName,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    try {
        $Output = & $Action 2>&1
        $Errors = @($Output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $Text = ($Output | Out-String).Trim()

        if ($Errors.Count -gt 0) {
            Write-Stage "$OperationName completed with reported errors." 'Warning'
            Add-Result -Category $Category -Name $OperationName -Status 'Warning' -Detail $Text
        }
        else {
            Write-Stage "$OperationName completed." 'Success'
            Add-Result -Category $Category -Name $OperationName -Status 'Completed' -Detail $Text
        }

        if ($Text) {
            Write-Host $Text -ForegroundColor DarkGray
        }

        return $Output
    }
    catch {
        Write-Stage ("{0} failed: {1}" -f $OperationName, $_.Exception.Message) 'Error'
        Add-Result -Category $Category -Name $OperationName -Status 'Failed' -Detail $_.Exception.Message
        return $null
    }
}

function Initialize-PowerShellGallery {
    Write-Stage 'Checking PSGallery registration and trust.'

    Invoke-SafeOperation -Category 'Bootstrap' -OperationName 'PSGallery configuration' -Action {
        $Repository = Get-PSRepository -Name 'PSGallery' -ErrorAction SilentlyContinue
        if (-not $Repository) {
            Register-PSRepository -Default -ErrorAction Stop
            $Repository = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop
        }

        if ($Repository.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction Stop
        }

        Get-PSRepository -Name 'PSGallery'
    } | Out-Null
}

function Initialize-PackageTooling {
    Write-Stage 'Bootstrapping package-management prerequisites.'

    if ($PowerShellVersion.Major -eq 5) {
        Invoke-SafeOperation -Category 'Bootstrap' -OperationName 'TLS 1.2 for Windows PowerShell' -Action {
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            [Net.ServicePointManager]::SecurityProtocol
        } | Out-Null
    }

    Invoke-SafeOperation -Category 'Bootstrap' -OperationName 'NuGet package provider' -Action {
        $Provider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $Provider) {
            $Provider = Install-PackageProvider -Name NuGet -Scope $ModuleScope -Force -ErrorAction Stop
        }
        $Provider
    } | Out-Null

    foreach ($BootstrapModule in @('PackageManagement', 'PowerShellGet')) {
        Invoke-SafeOperation -Category 'Bootstrap' -OperationName "$BootstrapModule availability" -Action {
            $Available = Get-Module -ListAvailable -Name $BootstrapModule |
                Sort-Object Version -Descending |
                Select-Object -First 1

            if (-not $Available) {
                Install-Module -Name $BootstrapModule -Repository PSGallery -Scope $ModuleScope -Force -AllowClobber -ErrorAction Stop
            }

            Get-Module -ListAvailable -Name $BootstrapModule |
                Sort-Object Version -Descending |
                Select-Object -First 1 Name, Version, ModuleBase
        } | Out-Null
    }
}

function Install-WindowsRsatCapabilities {
    if ($SkipWindowsCapabilities) {
        Write-Stage 'Windows capability installation was skipped by parameter.' 'Warning'
        return
    }

    if (-not $IsWindowsPlatform) {
        Write-Stage 'Windows capabilities are not applicable on this platform.' 'Warning'
        return
    }

    if (-not (Test-IsAdministrator)) {
        Write-Stage 'Not elevated. RSAT capability installation is skipped; existing modules will still be imported.' 'Warning'
        return
    }

    $GetCapability = Get-Command -Name Get-WindowsCapability -ErrorAction SilentlyContinue
    $AddCapability = Get-Command -Name Add-WindowsCapability -ErrorAction SilentlyContinue

    if (-not $GetCapability -or -not $AddCapability) {
        Write-Stage 'Windows Capability cmdlets are unavailable. This may be Windows Server; capability installation is skipped.' 'Warning'
        return
    }

    $Capabilities = @(
        'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0',
        'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0',
        'Rsat.ServerManager.Tools~~~~0.0.1.0'
    )

    foreach ($CapabilityName in $Capabilities) {
        Invoke-SafeOperation -Category 'WindowsCapability' -OperationName $CapabilityName -Action {
            $Capability = Get-WindowsCapability -Online -Name $CapabilityName -ErrorAction Stop
            if ($Capability.State -ne 'Installed') {
                $Capability = Add-WindowsCapability -Online -Name $CapabilityName -ErrorAction Stop
            }
            $Capability | Select-Object Name, State
        } | Out-Null
    }
}

function Install-MissingManagedModules {
    foreach ($ModuleDefinition in $ManagedModules) {
        $Name = $ModuleDefinition.Name
        $Module = Get-Module -ListAvailable -Name $Name |
            Sort-Object Version -Descending |
            Select-Object -First 1

        if ($Module) {
            Write-Stage ("{0} is available at version {1}." -f $Name, $Module.Version) 'Success'
            Add-Result -Category 'ModuleInstall' -Name $Name -Status 'AlreadyInstalled' -Detail ([string]$Module.Version)
            continue
        }

        Invoke-SafeOperation -Category 'ModuleInstall' -OperationName "Install $Name" -Action {
            $Parameters = @{
                Name = $Name
                Repository = 'PSGallery'
                Scope = $ModuleDefinition.Scope
                Force = $true
                ErrorAction = 'Stop'
            }

            if ($ModuleDefinition.AllowClobber) {
                $Parameters.AllowClobber = $true
            }

            Install-Module @Parameters
            Get-Module -ListAvailable -Name $Name |
                Sort-Object Version -Descending |
                Select-Object -First 1 Name, Version, ModuleBase
        } | Out-Null
    }
}

function Get-UpdateDecision {
    switch ($UpdateMode) {
        'Always' { return $true }
        'Never'  { return $false }
        default {
            $Response = Read-Host 'Check PSGallery and apply available updates to the managed module list? [Y/N]'
            return $Response -match '^[Yy]$'
        }
    }
}

function Update-ManagedModules {
    if (-not (Get-UpdateDecision)) {
        Write-Stage 'Module update phase skipped.' 'Warning'
        return
    }

    Write-Stage 'Checking managed modules for PSGallery updates.'

    foreach ($ModuleDefinition in $ManagedModules) {
        $TargetModuleName = [string]$ModuleDefinition.Name
        $TargetScope = [string]$ModuleDefinition.Scope
        $TargetAllowClobber = [bool]$ModuleDefinition.AllowClobber

        Invoke-SafeOperation -Category 'ModuleUpdate' -OperationName "Update check: $TargetModuleName" -Action {
            $Installed = Get-Module -ListAvailable -Name $TargetModuleName |
                Sort-Object Version -Descending |
                Select-Object -First 1

            $Latest = Find-Module -Name $TargetModuleName -Repository PSGallery -ErrorAction Stop

            if (-not $Installed) {
                $InstallParameters = @{
                    Name = $TargetModuleName
                    Repository = 'PSGallery'
                    Scope = $TargetScope
                    Force = $true
                    ErrorAction = 'Stop'
                }
                if ($TargetAllowClobber) { $InstallParameters.AllowClobber = $true }
                Install-Module @InstallParameters
                "${TargetModuleName}: installed gallery version $($Latest.Version)."
                return
            }

            if ([version]$Latest.Version -gt [version]$Installed.Version) {
                # Install-Module is intentionally used instead of Update-Module. It works
                # for modules visible to Get-Module even when PowerShellGet did not record
                # their original installation, and installs the newer version side-by-side.
                $InstallParameters = @{
                    Name = $TargetModuleName
                    Repository = 'PSGallery'
                    Scope = $TargetScope
                    Force = $true
                    ErrorAction = 'Stop'
                }
                if ($TargetAllowClobber) { $InstallParameters.AllowClobber = $true }
                Install-Module @InstallParameters

                $Updated = Get-Module -ListAvailable -Name $TargetModuleName |
                    Sort-Object Version -Descending |
                    Select-Object -First 1
                "${TargetModuleName}: updated from $($Installed.Version) to $($Updated.Version)."
            }
            else {
                "${TargetModuleName}: current version $($Installed.Version) is up to date."
            }
        } | Out-Null
    }
}

function Import-WindowsModule {
    param([Parameter(Mandatory = $true)][string]$Name)

    $Available = Get-Module -ListAvailable -Name $Name |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $Available) {
        Write-Stage "$Name is not available." 'Warning'
        Add-Result -Category 'ModuleImport' -Name $Name -Status 'Unavailable' -Detail 'Module not found.'
        return
    }

    Invoke-SafeOperation -Category 'ModuleImport' -OperationName "Import $Name" -Action {
        if ($PowerShellVersion.Major -ge 7) {
            try {
                Import-Module -Name $Name -Force -ErrorAction Stop
            }
            catch {
                Write-Warning "Direct import failed; retrying through Windows PowerShell compatibility: $($_.Exception.Message)"
                Import-Module -Name $Name -UseWindowsPowerShell -Force -ErrorAction Stop
            }
        }
        else {
            Import-Module -Name $Name -Force -ErrorAction Stop
        }
        Get-Module -Name $Name | Select-Object Name, Version, ModuleBase
    } | Out-Null
}

function Import-ManagedModules {
    foreach ($ModuleDefinition in $ManagedModules | Where-Object Import) {
        $TargetModuleName = [string]$ModuleDefinition.Name
        Invoke-SafeOperation -Category 'ModuleImport' -OperationName "Import $TargetModuleName" -Action {
            Import-Module -Name $TargetModuleName -Force -ErrorAction Stop
            Get-Module -Name $TargetModuleName | Select-Object Name, Version, ModuleBase
        } | Out-Null
    }

    Import-WindowsModule -Name 'ActiveDirectory'
    Import-WindowsModule -Name 'GroupPolicy'
}

function Import-LegacyOffensiveTools {
    if ($PowerShellVersion.Major -ne 5 -or $PowerShellVersion.Minor -ne 1) {
        Write-Stage "PowerShell $PowerShellVersion detected. PSReflect and PowerView are intentionally not loaded outside Windows PowerShell 5.1." 'Warning'
        return
    }

    $PsReflectPath = Join-Path -Path $ToolRoot -ChildPath 'PSReflect\PSReflect.psm1'
    if (Test-Path -LiteralPath $PsReflectPath) {
        Invoke-SafeOperation -Category 'LegacyTool' -OperationName 'Import PSReflect' -Action {
            Import-Module -Name $PsReflectPath -Force -ErrorAction Stop
            Get-Module -Name PSReflect | Select-Object Name, Version, ModuleBase
        } | Out-Null
    }
    else {
        Write-Stage "PSReflect was not found at $PsReflectPath" 'Warning'
    }

    $PowerViewPath = Join-Path -Path $ToolRoot -ChildPath 'PowerSploit\Recon\PowerView.ps1'
    if (Test-Path -LiteralPath $PowerViewPath) {
        Invoke-SafeOperation -Category 'LegacyTool' -OperationName 'Load PowerView' -Action {
            . $PowerViewPath
            "PowerView dot-sourced from $PowerViewPath"
        } | Out-Null
    }
    else {
        Write-Stage "PowerView was not found at $PowerViewPath" 'Warning'
    }
}

function Initialize-AzureCliExtension {
    if ($SkipAzureCliConfiguration) {
        Write-Stage 'Azure CLI extension configuration skipped by parameter.' 'Warning'
        return
    }

    if (-not (Get-Command -Name az -ErrorAction SilentlyContinue)) {
        Write-Stage 'Azure CLI was not found; Automation extension configuration skipped.' 'Warning'
        return
    }

    Invoke-SafeOperation -Category 'AzureCLI' -OperationName 'Azure Automation CLI extension' -Action {
        $InstalledExtensions = az extension list --output json 2>$null | ConvertFrom-Json
        if ($InstalledExtensions.name -notcontains 'automation') {
            az extension add --name automation --only-show-errors 2>$null
        }
        az config set extension.use_dynamic_install=yes_without_prompt --only-show-errors 2>$null
        az extension show --name automation --output table 2>$null
    } | Out-Null
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ' PowerShell Work Preflight' -ForegroundColor Cyan
Write-Host (" Version:          {0}" -f $ScriptVersion) -ForegroundColor Cyan
Write-Host (" PowerShell:       {0} ({1})" -f $PowerShellVersion, $PSVersionTable.PSEdition) -ForegroundColor Yellow
Write-Host (" Module scope:     {0}" -f $ModuleScope) -ForegroundColor Yellow
Write-Host (" Tool root:        {0}" -f $ToolRoot) -ForegroundColor Yellow
Write-Host (" Elevated:         {0}" -f (Test-IsAdministrator)) -ForegroundColor Yellow
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ''

if ($SetCurrentUserExecutionPolicy -and $IsWindowsPlatform) {
    Invoke-SafeOperation -Category 'Configuration' -OperationName 'Current-user execution policy' -Action {
        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -ErrorAction Stop
        Get-ExecutionPolicy -List
    } | Out-Null
}

Initialize-PowerShellGallery
Initialize-PackageTooling
Install-WindowsRsatCapabilities
Install-MissingManagedModules
Update-ManagedModules
Import-ManagedModules
Import-LegacyOffensiveTools
Initialize-AzureCliExtension

Write-Host ''
Write-Host 'LOADED MODULES' -ForegroundColor Green
Get-Module -Name @(
    'AADInternals',
    'AADInternals-Endpoints',
    'DSInternals',
    'ActiveDirectory',
    'GroupPolicy',
    'PSPreworkout',
    'PSReflect'
) -ErrorAction SilentlyContinue |
    Sort-Object Name |
    Select-Object Name, Version, ModuleBase |
    Format-Table -AutoSize

if (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue) {
    $CurrentAzContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($CurrentAzContext) {
        Write-Host ''
        Write-Host 'PERSISTED AZ POWERSHELL CONTEXT' -ForegroundColor Green
        Write-Host 'This is cached Az PowerShell state; it is not proof of the current Windows or Graph identity.' -ForegroundColor Yellow
        $CurrentAzContext |
            Select-Object @{Name='Account';Expression={$_.Account.Id}},
                @{Name='Tenant';Expression={$_.Tenant.Id}},
                @{Name='Subscription';Expression={$_.Subscription.Name}} |
            Format-List

        if ($ExpectedAzAccount -and $CurrentAzContext.Account.Id -ne $ExpectedAzAccount) {
            Write-Stage ("Persisted Az account '$($CurrentAzContext.Account.Id)' does not match expected account '$ExpectedAzAccount'. The script did not clear or replace the context.") 'Warning'
            Add-Result -Category 'AzureContext' -Name 'Persisted Az account' -Status 'Warning' -Detail "Actual=$($CurrentAzContext.Account.Id); Expected=$ExpectedAzAccount"
        }
    }
}

Write-Host ''
Write-Host 'PREFLIGHT SUMMARY' -ForegroundColor Green
$Results |
    Group-Object Status |
    Sort-Object Name |
    Select-Object Name, Count |
    Format-Table -AutoSize

if ($PowerShellVersion.Major -ge 7) {
    Write-Host 'For the PSReflect and PowerView path, launch Windows PowerShell 5.1 and run this same script:' -ForegroundColor Yellow
    Write-Host '  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-PowerShellWorkPreflight-v2.1.0.ps1' -ForegroundColor Yellow
}

Write-Stage 'Preflight completed. Review any warnings above; unrelated operations continued.' 'Success'
