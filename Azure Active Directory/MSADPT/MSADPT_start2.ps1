# Requires -Version 7.0

<#
.SYNOPSIS
    MSADPT_start2.ps1 - Initial setup script for the MSADPT tool.
    This script accepts all required input via command-line parameters,
    logs the initial environment, and discovers Domain Controllers and ADCS servers
    within the specified domain. It produces CSV outputs for environment details,
    discovered DCs, and discovered ADCS servers.

.DESCRIPTION
    This script is the entry point for the MSADPT (Microsoft AD Pen Test) tool.
    It performs the following steps:
    1. Imports the MSADPT helper module for standardized logging.
    2. Gathers and logs initial environmental information (date, computer name, IP config, domain info).
    3. Verifies the presence of necessary PowerShell modules (e.g., ActiveDirectory).
    4. Discovers all accessible Domain Controllers in the specified domain.
    5. Discovers all accessible Active Directory Certificate Services (ADCS) servers.
    6. Stores the gathered information into structured CSV files for use by subsequent scripts.

.PARAMETER Credential
    Domain credential to use for all Active Directory enumeration operations.
    Example:
        -Credential (Get-Credential)

.PARAMETER DomainFQDN
    Fully qualified domain name to enumerate.
    Example:
        -DomainFQDN "foo.net"

.PARAMETER EnvironmentOutputCsvPath
    Output CSV path for the environment details.
    Example:
        -EnvironmentOutputCsvPath "C:\temp\MSADPT_Output\MSADPT_Environment.csv"

.PARAMETER DCOutputCsvPath
    Output CSV path for the discovered Domain Controllers.
    Example:
        -DCOutputCsvPath "C:\temp\MSADPT_Output\MSADPT_DCs.csv"

.PARAMETER ADCSOutputCsvPath
    Output CSV path for the discovered ADCS servers.
    Example:
        -ADCSOutputCsvPath "C:\temp\MSADPT_Output\MSADPT_ADCS.csv"

.PARAMETER AdServer
    bootstrap Domain Controller / ADWS-capable server to use.


.OUTPUTS
    - Environment CSV at the path specified by -EnvironmentOutputCsvPath
    - Domain Controllers CSV at the path specified by -DCOutputCsvPath
    - ADCS servers CSV at the path specified by -ADCSOutputCsvPath

.EXAMPLE
    .\MSADPT_start2.ps1 `
        -Credential (Get-Credential) `
        -DomainFQDN "foo.net" `
        -AdServer "dc03.foo.net" `
        -EnvironmentOutputCsvPath "C:\temp\MSADPT_Output\MSADPT_Environment.csv" `
        -DCOutputCsvPath "C:\temp\MSADPT_Output\MSADPT_DCs.csv" `
        -ADCSOutputCsvPath "C:\temp\MSADPT_Output\MSADPT_ADCS.csv"
#>

param(
    [Parameter(Mandatory)]
    [PSCredential]$Credential,

    [Parameter(Mandatory)]
    [string]$DomainFQDN,

    [Parameter(Mandatory)]
    [string]$EnvironmentOutputCsvPath,

    [Parameter(Mandatory)]
    [string]$DCOutputCsvPath,

    [Parameter(Mandatory)]
    [string]$ADCSOutputCsvPath,

	[Parameter(Mandatory)]
    [string]$AdServer
)

# --- Ensure parent folders exist for all output files ---
$allOutputPaths = @(
    $EnvironmentOutputCsvPath,
    $DCOutputCsvPath,
    $ADCSOutputCsvPath
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

foreach ($path in $allOutputPaths) {
    $parent = Split-Path -Path $path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
}

# --- Import helper module ---
$helpersModulePath = Join-Path $PSScriptRoot 'MSADPT.Helpers.psm1'

if (-not (Test-Path -LiteralPath $helpersModulePath -PathType Leaf)) {
    Write-Error "Required helper module not found at '$helpersModulePath'. Aborting."
    exit 1
}

Import-Module $helpersModulePath -Force -ErrorAction Stop

$rootDSE = Test-MSADPTADConnectivity -Credential $Credential -AdServer $AdServer

if (-not $rootDSE) {
    Write-MSADPTLog -Message "Cannot continue because AD connectivity pre-flight failed." -Level 'ERROR'
    exit 1
}

Write-MSADPTLog -Message "MSADPT_start.ps1 started. Beginning initial environment and AD/ADCS discovery." -Level 'INFO'
Write-MSADPTLog -Message "DomainFQDN: $DomainFQDN" -Level 'INFO'
Write-MSADPTLog -Message "Environment output CSV: $EnvironmentOutputCsvPath" -Level 'INFO'
Write-MSADPTLog -Message "DC output CSV: $DCOutputCsvPath" -Level 'INFO'
Write-MSADPTLog -Message "ADCS output CSV: $ADCSOutputCsvPath" -Level 'INFO'

# --- Module and tool pre-checks ---
Write-MSADPTLog -Message "Checking required PowerShell modules and tools." -Level 'INFO'

$RequiredModules = @('ActiveDirectory')
foreach ($module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-MSADPTLog -Message "Required PowerShell module '$module' is not available. Aborting." -Level 'ERROR'
        exit 1
    }

    if (-not (Get-Module -Name $module)) {
        Write-MSADPTLog -Message "Importing PowerShell module: $module" -Level 'INFO'
        Import-Module $module -ErrorAction Stop
    }
}

$RequiredCommands = @('nltest', 'net', 'wmic', 'dsregcmd', 'gpresult')
foreach ($cmd in $RequiredCommands) {
    if (-not (Get-Command -Name $cmd -ErrorAction SilentlyContinue)) {
        Write-MSADPTLog -Message "Required command-line tool '$cmd' was not found in PATH. Aborting." -Level 'ERROR'
        exit 1
    }
}

Write-MSADPTLog -Message "All required modules and tools are available." -Level 'INFO'

# --- Determine bootstrap AD server ---
$BootstrapServer = $null

try {
    if (-not [string]::IsNullOrWhiteSpace($AdServer)) {
        $BootstrapServer = $AdServer
        Write-MSADPTLog -Message "Using operator-supplied AD server '$BootstrapServer' as bootstrap server." -Level 'INFO'
    }
    else {
        $BootstrapServer = (Get-ADDomainController `
            -Discover `
            -ForceDiscover `
            -DomainName $DomainFQDN `
            -Service ADWS `
            -Credential $Credential `
            -ErrorAction Stop).HostName

        Write-MSADPTLog -Message "Discovered ADWS-capable Domain Controller '$BootstrapServer' for bootstrap operations." -Level 'WARNING'
    }
}
catch {
    Write-MSADPTLog -Message "Failed to determine a bootstrap AD server for domain '$DomainFQDN': $($_.Exception.Message)" -Level 'ERROR'
    exit 1
}

# --- Environment Logging ---
Write-MSADPTLog -Message "Gathering initial environmental information." -Level 'INFO'

<# When a command inside that object construction fails badly enough, the whole assignment can fail to 
produce a usable object, leaving $EnvironmentInfo as $null.
So If you cannot connect to the DC, say over a VPN, this is normal... #>

$computerInfo = Get-ComputerInfo
$ipConfigText = (Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias, AddressFamily | Out-String).Trim()

$EnvironmentInfo = [PSCustomObject]@{
    Timestamp         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Username          = $Credential.UserName
    LocalComputerName = $computerInfo.CsName
    OperatingSystem   = $computerInfo.OsDisplayVersion
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    DomainName        = $(try { (Get-ADDomain -Server $BootstrapServer -Credential $Credential -ErrorAction Stop).NetBIOSName } catch { $null })
    DomainFQDN        = $DomainFQDN
    BootstrapServer   = $BootstrapServer
    IPConfiguration   = $ipConfigText
    IsHybridJoined    = (dsregcmd /status | Select-String "AzureAdJoined").ToString().Contains("YES")
    LocalAdminCheck   = $(try { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $false })
}

if ($null -ne $EnvironmentInfo) {
    $EnvironmentInfo | Export-Csv -Path $EnvironmentOutputCsvPath -NoTypeInformation -Force -ErrorAction Stop
    Write-MSADPTLog -Message "Initial environment information saved to '$EnvironmentOutputCsvPath'." -Level 'WARNING'
}
else {
    Write-MSADPTLog -Message "Environment information object was null; environment CSV export skipped." -Level 'ERROR'
    exit 1
}

# --- Discover Domain Controllers ---
<# If this fails, the DC cannot be infered, likely the machine is not domain joined.
Easy workaround, add a domainFQN entry in the .config file. #>
Write-MSADPTLog -Message "Discovering Domain Controllers in '$DomainFQDN'." -Level 'INFO'

$DCs = @()
try {
    $DCs = Get-ADDomainController `
        -Filter * `
        -Server $BootstrapServer `
        -Credential $Credential `
        -ErrorAction Stop |
        Select-Object Name, HostName, IPv4Address, IsGlobalCatalog, IsReadOnly, Site, OperatingSystem, Forest, Domain

    if (@($DCs).Count -gt 0) {
        $DCs | Export-Csv -Path $DCOutputCsvPath -NoTypeInformation -Force -ErrorAction Stop
        Write-MSADPTLog -Message "Discovered $(@($DCs).Count) Domain Controller(s). Details saved to '$DCOutputCsvPath'." -Level 'WARNING'

        $DCs | ForEach-Object {
            Write-MSADPTLog -Message "  - $($_.Name) ($($_.IPv4Address))" -Level 'INFO'
        }
    }
    else {
        Write-MSADPTLog -Message "No Domain Controllers were returned for '$DomainFQDN'." -Level 'WARNING'
    }
}
catch {
    Write-MSADPTLog -Message "Failed to discover Domain Controllers: $($_.Exception.Message)" -Level 'ERROR'
    exit 1
}

# --- Discover Active Directory Certificate Services (ADCS) Servers ---
Write-MSADPTLog -Message "Discovering Active Directory Certificate Services (ADCS) servers by querying pKIEnrollmentService objects." -Level 'INFO'

$AllADCSservers = @()

try {
    foreach ($DC in $DCs) {
        $DCServer = if (-not [string]::IsNullOrWhiteSpace($DC.HostName)) { $DC.HostName } else { $DC.Name }

        if ([string]::IsNullOrWhiteSpace($DCServer)) {
            Write-MSADPTLog -Message "Skipping a DC entry because neither HostName nor Name is populated." -Level 'WARNING'
            continue
        }

        try {
            Write-MSADPTLog -Message "Querying DC '$DCServer' for ADCS Enterprise CA objects." -Level 'INFO'

            $rootDSE = Get-ADRootDSE -Server $DCServer -Credential $Credential -ErrorAction Stop
            $searchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"

            Write-MSADPTLog -Message "ADCS search base for '$DCServer': $searchBase" -Level 'INFO'

            $CurrentADCS = Get-ADObject `
                -LDAPFilter "(objectClass=pKIEnrollmentService)" `
                -SearchBase $searchBase `
                -SearchScope OneLevel `
                -Properties objectGUID, cn, dNSHostName, displayName, description, certificateTemplates, cACertificate `
                -Server $DCServer `
                -Credential $Credential `
                -ErrorAction Stop |
                Select-Object `
                    Name,
                    objectGUID,
                    cn,
                    dNSHostName,
                    displayName,
                    description,
                    certificateTemplates,
                    @{Name='ServerRole';Expression={'Enterprise CA'}},
                    @{Name='DiscoveredFromDC';Expression={$DCServer}}

            if (@($CurrentADCS).Count -gt 0) {
                Write-MSADPTLog -Message "DC '$DCServer' returned $(@($CurrentADCS).Count) ADCS Enterprise CA object(s)." -Level 'INFO'
                $AllADCSservers += $CurrentADCS
            }
            else {
                Write-MSADPTLog -Message "DC '$DCServer' returned no ADCS Enterprise CA objects." -Level 'WARNING'
            }
        }
        catch {
            Write-MSADPTLog -Message "Failed querying DC '$DCServer' for ADCS objects: $($_.Exception.Message)" -Level 'ERROR'
        }
    }

    $UniqueADCSservers = $AllADCSservers |
        Group-Object {
            if ($_.objectGUID) {
                $_.objectGUID.Guid
            }
            elseif (-not [string]::IsNullOrWhiteSpace($_.dNSHostName)) {
                $_.dNSHostName.ToLowerInvariant()
            }
            elseif (-not [string]::IsNullOrWhiteSpace($_.cn)) {
                $_.cn.ToLowerInvariant()
            }
            else {
                $_.Name.ToLowerInvariant()
            }
        } |
        ForEach-Object { $_.Group[0] } |
        Sort-Object dNSHostName, cn

    if (@($UniqueADCSservers).Count -gt 0) {
        $UniqueADCSservers |
            Select-Object Name, cn, dNSHostName, displayName, description, certificateTemplates, ServerRole |
            Export-Csv -Path $ADCSOutputCsvPath -NoTypeInformation -Force -ErrorAction Stop

        Write-MSADPTLog -Message "Discovered $(@($UniqueADCSservers).Count) unique ADCS server(s). Details saved to '$ADCSOutputCsvPath'." -Level 'WARNING'

        $UniqueADCSservers | ForEach-Object {
            $hostLabel = if (-not [string]::IsNullOrWhiteSpace($_.dNSHostName)) { $_.dNSHostName } else { $_.cn }
            Write-MSADPTLog -Message "  - $hostLabel (Role: $($_.ServerRole))" -Level 'INFO'
        }
    }
    else {
        Write-MSADPTLog -Message "No ADCS servers were found after querying all discovered DCs." -Level 'WARNING'
    }
}
catch {
    Write-MSADPTLog -Message "Failed during ADCS discovery: $($_.Exception.Message)" -Level 'ERROR'
    exit 1
}

Write-MSADPTLog -Message "MSADPT_start.ps1 completed successfully." -Level 'INFO'
Write-MSADPTLog -Message "The collected data can now be used as input for subsequent analysis scripts." -Level 'INFO'
