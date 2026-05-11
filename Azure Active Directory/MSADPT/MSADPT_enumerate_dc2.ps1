# Requires -Version 7.0

<#
.SYNOPSIS
     - Enumerates details of discovered Domain Controllers.

.DESCRIPTION
    This script performs detailed Active Directory reconnaissance against
    Domain Controllers listed in an input CSV file produced by MSADPT_start.ps1.

    All Active Directory operations:
    - use explicit credentials
    - target an explicit Domain Controller
    - do NOT assume the host is domain joined

    All output paths are explicitly supplied as parameters.

.PARAMETER InputDcCsvPath
    Path to the CSV file containing discovered Domain Controllers.
    Example:
        C:\temp\MSADPT_Output\MSADPT_DCs.csv

.PARAMETER OutputBaseDir
    Base directory where per-DC output folders and CSVs will be written.

.PARAMETER Credential
    Domain credential used for all Active Directory enumeration.

.PARAMETER DomainFQDN
    Target Active Directory domain (e.g. foo.bar).

.PARAMETER AdServer
    Domain Controller / ADWS-capable server to use for all AD queries
    (e.g. dc01.foo.bar).

.EXAMPLE
    .\MSADPT_enumerate_dc2.ps1 `
        -InputDcCsvPath "C:\temp\MSADPT_Output\MSADPT_DCs.csv" `
        -OutputBaseDir "C:\temp\MSADPT_Output\DC_Enumeration" `
        -Credential (Get-Credential) `
        -DomainFQDN "foo.bar" `
        -AdServer "dc01.foo.bar"
#>

param(
    [Parameter(Mandatory)]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "Input file '$_' does not exist."
        }
        $true
    })]
    [string]$InputDcCsvPath,

    [Parameter(Mandatory)]
    [string]$OutputBaseDir,

    [Parameter(Mandatory)]
    [PSCredential]$Credential,

    [Parameter(Mandatory)]
    [string]$DomainFQDN,

    [Parameter(Mandatory)]
    [string]$AdServer
)

# ---------------------------------------------------------------------
# Import helper module (same folder as script)
# ---------------------------------------------------------------------
$helpersModulePath = Join-Path $PSScriptRoot 'MSADPT.Helpers.psm1'

if (-not (Test-Path -LiteralPath $helpersModulePath)) {
    Write-Error "Required helper module not found at '$helpersModulePath'. Aborting."
    exit 1
}

Import-Module $helpersModulePath -Force -ErrorAction Stop

Write-MSADPTLog -Message "MSADPT_enumerate_dc.ps1 starting." -Level 'INFO'
Write-MSADPTLog -Message "DomainFQDN : $DomainFQDN"
Write-MSADPTLog -Message "AdServer   : $AdServer"
Write-MSADPTLog -Message "Input CSV  : $InputDcCsvPath"
Write-MSADPTLog -Message "Output Dir : $OutputBaseDir"

# ---------------------------------------------------------------------
# Pre-flight: AD connectivity check
# ---------------------------------------------------------------------
$rootDSE = Test-MSADPTADConnectivity -Credential $Credential -AdServer $AdServer
if (-not $rootDSE) {
    Write-MSADPTLog -Message "Active Directory connectivity pre-flight failed. Aborting." -Level 'ERROR'
    exit 1
}

# ---------------------------------------------------------------------
# Ensure output directory exists
# ---------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $OutputBaseDir)) {
    New-Item -Path $OutputBaseDir -ItemType Directory -Force | Out-Null
}

# ---------------------------------------------------------------------
# Import DC list
# ---------------------------------------------------------------------
$DCs = Import-Csv -Path $InputDcCsvPath
if (-not $DCs) {
    Write-MSADPTLog -Message "No Domain Controllers found in input CSV. Exiting." -Level 'WARNING'
    exit 0
}

# ---------------------------------------------------------------------
# Iterate each Domain Controller
# ---------------------------------------------------------------------
foreach ($DC in $DCs) {

    $DCName = $DC.Name
    $DCIp   = $DC.IPv4Address

    Write-MSADPTLog -Message "--------------------------------------------------------"
    Write-MSADPTLog -Message "Processing Domain Controller: $DCName ($DCIp)"
    Write-MSADPTLog -Message "--------------------------------------------------------"

    $CurrentDCOutputDir = Join-Path $OutputBaseDir $DCName
    if (-not (Test-Path $CurrentDCOutputDir)) {
        New-Item -Path $CurrentDCOutputDir -ItemType Directory -Force | Out-Null
    }

    $DCErrors = @()

    # -----------------------------------------------------------------
    # 1. Connectivity Checks
    # -----------------------------------------------------------------
    if (Prompt-User -PromptText "Perform connectivity checks for ${DCName}?") {

        Write-MSADPTLog -Message "Performing connectivity checks to $DCName ($DCIp)."

        if (-not (Test-Connection -ComputerName $DCIp -Count 1 -Quiet)) {
            Write-MSADPTLog -Message "Ping failed to $DCIp." -Level 'WARNING'
            $DCErrors += "Ping failed"
        }

        foreach ($port in 445,389,9389,135) {
            $result = Test-NetConnection -ComputerName $DCIp -Port $port -InformationLevel Quiet
            if ($result) {
                Write-MSADPTLog -Message "Port $port reachable on $DCIp."
            } else {
                Write-MSADPTLog -Message "Port $port NOT reachable on $DCIp." -Level 'WARNING'
                $DCErrors += "Port $port unreachable"
            }
        }
    }

    # -----------------------------------------------------------------
    # 2. Basic DC Information
    # -----------------------------------------------------------------
    if (Prompt-User -PromptText "Retrieve detailed DC information for ${DCName}?") {
        try {
            $DCInfo = Get-ADDomainController `
                -Identity $DCName `
                -Server $AdServer `
                -Credential $Credential `
                -ErrorAction Stop

            $DCInfo |
                Select-Object Name, HostName, IPv4Address, OperatingSystem, Site, IsGlobalCatalog, IsReadOnly |
                Export-Csv -Path (Join-Path $CurrentDCOutputDir "MSADPT_DC_Details_$DCName.csv") -NoTypeInformation -Force

            Write-MSADPTLog -Message "DC details saved for $DCName."
        }
        catch {
            Write-MSADPTLog -Message "Failed retrieving DC info for ${DCName}: $($_.Exception.Message)" -Level 'ERROR'
            $DCErrors += "DC info failed"
        }
    }

    # -----------------------------------------------------------------
    # Final DC summary
    # -----------------------------------------------------------------
    if ($DCErrors.Count -gt 0) {
        Write-MSADPTLog -Message "Finished $DCName with $($DCErrors.Count) warning/error(s)." -Level 'WARNING'
        $DCErrors | ForEach-Object {
            Write-MSADPTLog -Message "  - $_" -Level 'WARNING'
        }
    }
    else {
        Write-MSADPTLog -Message "Finished $DCName successfully."
    }
}

Write-MSADPTLog -Message "MSADPT_enumerate_dc.ps1 completed." -Level 'INFO'
