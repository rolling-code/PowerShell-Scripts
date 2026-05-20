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

.OUTPUTS
    - MSADPT_DC_Details_<DCName>_<timestamp>.csv
        Detailed Domain Controller information.

    - MSADPT_DC_Kerberoastable_<DCName>_<timestamp>.csv
        User accounts with Service Principal Names.
        Consumed by MSADPT_exploit_privesc_initial.ps1.
        Required downstream columns:
          - SamAccountName
          - ServicePrincipalName

    - MSADPT_DC_ASREPRoastable_<DCName>_<timestamp>.csv
        User accounts with Kerberos pre-authentication disabled.
        Consumed by MSADPT_exploit_privesc_initial.ps1.
        Required downstream columns:
          - SamAccountName
          - UserPrincipalName

    - MSADPT_DC_LAPSInfo_<DCName>_<timestamp>.csv
        LAPS-related computer records and reader group information.
        Consumed by MSADPT_exploit_privesc_initial.ps1.
		Required downstream columns:
		  - DCName
		  - LAPS_ComputerDetails

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
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
            throw "Input file '$_' does not exist."
        }
        $true
    })]
    [string]$InputDcCsvPath,

    [Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
    [string]$OutputBaseDir,

    [Parameter(Mandatory)]
	[ValidateNotNull()]
    [PSCredential]$Credential,

    [Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
    [string]$DomainFQDN,

    [Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
    [string]$AdServer
)

# ---------------------------------------------------------------------
# Import helper module (same folder as script)
# ---------------------------------------------------------------------
$helpersModulePath = Join-Path $PSScriptRoot 'MSADPT.Helpers.psm1'

if (-not (Test-Path -LiteralPath $helpersModulePath -PathType Leaf)) {
    Write-Error "Required helper module not found at '$helpersModulePath'. Aborting."
    exit 1
}

Import-Module $helpersModulePath -Force -ErrorAction Stop

# ---------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------
$ScriptStartTime = Get-Date -Format "yyyyMMdd"

Write-MSADPTLog -Message "MSADPT_enumerate_dc2.ps1 starting." -Level 'INFO'
Write-MSADPTLog -Message "DomainFQDN : $DomainFQDN"
Write-MSADPTLog -Message "AdServer   : $AdServer"
Write-MSADPTLog -Message "Input CSV  : $InputDcCsvPath"
Write-MSADPTLog -Message "Output Dir : $OutputBaseDir"

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

$requiredColumns = @('Name', 'IPv4Address')
$actualColumns = @($DCs[0].PSObject.Properties.Name)

foreach ($column in $requiredColumns) {
    if ($actualColumns -notcontains $column) {
        Write-MSADPTLog -Message "Input CSV is missing required column '$column'. Aborting." -Level 'ERROR'
        exit 1
    }
}


$RequiredModules = @('ActiveDirectory')

foreach ($module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-MSADPTLog -Message "Required module '$module' is not available. Aborting." -Level 'ERROR'
        exit 1
    }

    if (-not (Get-Module -Name $module)) {
        Import-Module $module -ErrorAction Stop
        Write-MSADPTLog -Message "Imported module '$module'." -Level 'INFO'
    }
}

$adSplat = New-MSADPTAdCommandSplat -Server $AdServer -Credential $Credential

$rootDSE = Test-MSADPTADConnectivity -Credential $Credential -AdServer $AdServer
if (-not $rootDSE) {
    Write-MSADPTLog -Message "Active Directory connectivity pre-flight failed. Aborting." -Level 'ERROR'
    exit 1
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
                Export-Csv -Path (Join-Path $CurrentDCOutputDir "MSADPT_DC_Details_${DCName}_$ScriptStartTime.csv") -NoTypeInformation -Force

            Write-MSADPTLog -Message "DC details saved for $DCName."
        }
        catch {
            Write-MSADPTLog -Message "Failed retrieving DC info for ${DCName}: $($_.Exception.Message)" -Level 'ERROR'
            $DCErrors += "DC info failed"
        }
    }
	# -----------------------------------------------------------------
    # 3. Kerberoastable Account Discovery
    # -----------------------------------------------------------------
    if (Prompt-User -PromptText "Identify Kerberoastable accounts (user accounts with SPNs) from ${DCName}?") {
        Write-MSADPTLog -Message "Identifying Kerberoastable accounts using explicit AD server '$AdServer'." -Level 'INFO'

        try {
            $KerberoastableAccounts = @(
                Get-ADUser @adSplat `
                    -LDAPFilter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' `
                    -Properties ServicePrincipalName, UserPrincipalName, Enabled, LastLogonDate, PasswordLastSet, DistinguishedName `
                    -ErrorAction Stop
            )

            if ($KerberoastableAccounts.Count -gt 0) {
                $KRBCsvPath = Join-Path $CurrentDCOutputDir "MSADPT_DC_Kerberoastable_${DCName}_$ScriptStartTime.csv"

                $KerberoastableAccounts |
                    Select-Object `
                        Name,
                        SamAccountName,
                        UserPrincipalName,
                        @{
                            Name       = 'ServicePrincipalName'
                            Expression = { @($_.ServicePrincipalName) -join ';' }
                        },
                        Enabled,
                        LastLogonDate,
                        PasswordLastSet,
                        DistinguishedName |
                    Export-Csv -Path $KRBCsvPath -NoTypeInformation -Force

                Write-MSADPTLog -Message "Identified $($KerberoastableAccounts.Count) Kerberoastable account(s). Details saved to '$KRBCsvPath'." -Level 'WARNING'
            }
            else {
                Write-MSADPTLog -Message "No Kerberoastable accounts found." -Level 'INFO'
            }
        }
        catch {
            Write-MSADPTLog -Message "Failed to identify Kerberoastable accounts from ${DCName}: $($_.Exception.Message)" -Level 'ERROR'
            $DCErrors += "Kerberoastable account discovery failed"
        }
    }
    else {
        Write-MSADPTLog -Message "Skipping Kerberoastable account identification for $DCName." -Level 'INFO'
    }
	
	# -----------------------------------------------------------------
    # 4. AS-REP Roastable Account Discovery
    # -----------------------------------------------------------------
    if (Prompt-User -PromptText "Identify AS-REP Roastable accounts (DONT_REQ_PREAUTH) from ${DCName}?") {
        Write-MSADPTLog -Message "Identifying AS-REP Roastable accounts using explicit AD server '$AdServer'." -Level 'INFO'

        try {
            # 4194304 / 0x400000 = DONT_REQ_PREAUTH
            $ASRepRoastableAccounts = @(
                Get-ADUser @adSplat `
                    -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' `
                    -Properties UserPrincipalName, ServicePrincipalName, UserAccountControl, Enabled, LastLogonDate, PasswordLastSet, DistinguishedName `
                    -ErrorAction Stop
            )

            if ($ASRepRoastableAccounts.Count -gt 0) {
                $ASRCsvPath = Join-Path $CurrentDCOutputDir "MSADPT_DC_ASREPRoastable_${DCName}_$ScriptStartTime.csv"

                $ASRepRoastableAccounts |
                    Select-Object `
                        Name,
                        SamAccountName,
                        UserPrincipalName,
                        @{
                            Name       = 'ServicePrincipalName'
                            Expression = { @($_.ServicePrincipalName) -join ';' }
                        },
                        UserAccountControl,
                        Enabled,
                        LastLogonDate,
                        PasswordLastSet,
                        DistinguishedName |
                    Export-Csv -Path $ASRCsvPath -NoTypeInformation -Force

                Write-MSADPTLog -Message "Identified $($ASRepRoastableAccounts.Count) AS-REP Roastable account(s). Details saved to '$ASRCsvPath'." -Level 'WARNING'
            }
            else {
                Write-MSADPTLog -Message "No AS-REP Roastable accounts found." -Level 'INFO'
            }
        }
        catch {
            Write-MSADPTLog -Message "Failed to identify AS-REP Roastable accounts from ${DCName}: $($_.Exception.Message)" -Level 'ERROR'
            $DCErrors += "AS-REP Roastable account discovery failed"
        }
    }
    else {
        Write-MSADPTLog -Message "Skipping AS-REP Roastable account identification for $DCName." -Level 'INFO'
    }
	
	# -----------------------------------------------------------------
    # 5. LAPS Configuration / Exposure Review
    # -----------------------------------------------------------------
    if (Prompt-User -PromptText "Enumerate LAPS configuration and readable password attributes from ${DCName}?") {
        Write-MSADPTLog -Message "Querying LAPS-related computer attributes using explicit AD server '$AdServer'." -Level 'INFO'

        try {
            $schemaNC = $rootDSE.schemaNamingContext

            $HasWindowsLAPS = $false
            try {
                $HasWindowsLAPS = $null -ne (
                    Get-ADObject @adSplat `
                        -SearchBase $schemaNC `
                        -LDAPFilter '(lDAPDisplayName=msLAPS-Password)' `
                        -ErrorAction SilentlyContinue
                )
            }
            catch {
                Write-MSADPTLog -Message "Could not confirm Windows LAPS schema support: $($_.Exception.Message)" -Level 'WARNING'
                $HasWindowsLAPS = $false
            }

            $LAPSProperties = @(
                'ms-Mcs-AdmPwd',
                'ms-Mcs-AdmPwdExpirationTime'
            )

            $LAPSLdapFilter = '(ms-Mcs-AdmPwdExpirationTime=*)'

            if ($HasWindowsLAPS) {
                $LAPSProperties += @(
                    'msLAPS-Password',
                    'msLAPS-PasswordExpirationTime'
                )

                $LAPSLdapFilter = '(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*))'
            }

            $LAPSComputers = @(
                Get-ADComputer @adSplat `
                    -LDAPFilter $LAPSLdapFilter `
                    -Properties $LAPSProperties `
                    -ErrorAction Stop
            )

            $LAPSReaders = @()
            try {
                $LAPSReaders = @(
                    Get-ADGroup @adSplat `
                        -Filter "Name -like '*LAPS*Reader*'" `
                        -Properties Member `
                        -ErrorAction Stop
                )
            }
            catch {
                Write-MSADPTLog -Message "Could not enumerate LAPS reader groups: $($_.Exception.Message)" -Level 'WARNING'
                $LAPSReaders = @()
            }

            $LAPSInfo = [PSCustomObject]@{
                Timestamp             = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                DCName                = $DCName
                WindowsLAPS_Supported = $HasWindowsLAPS
                LAPS_EnabledComputers = @($LAPSComputers).Count
                LAPS_ComputerDetails  = (
                    $LAPSComputers |
                        Select-Object `
                            Name,
                            DNSHostName,
                            DistinguishedName,
                            'ms-Mcs-AdmPwd',
                            'ms-Mcs-AdmPwdExpirationTime',
                            'msLAPS-Password',
                            'msLAPS-PasswordExpirationTime' |
                        ConvertTo-Json -Compress -Depth 5
                )
                LAPS_ReaderGroups     = (
                    $LAPSReaders |
                        Select-Object `
                            Name,
                            SamAccountName,
                            DistinguishedName,
                            @{
                                Name       = 'Members'
                                Expression = { @($_.Member) -join ';' }
                            } |
                        ConvertTo-Json -Compress -Depth 5
                )
            }

            $LAPSCsvPath = Join-Path $CurrentDCOutputDir "MSADPT_DC_LAPSInfo_${DCName}_$ScriptStartTime.csv"
            $LAPSInfo | Export-Csv -Path $LAPSCsvPath -NoTypeInformation -Force -ErrorAction Stop

            Write-MSADPTLog -Message "LAPS configuration details saved to '$LAPSCsvPath'. Password fields are populated only if the supplied credential has read rights." -Level 'WARNING'
        }
        catch {
            Write-MSADPTLog -Message "Failed to enumerate LAPS configuration from ${DCName}: $($_.Exception.Message)" -Level 'ERROR'
            $DCErrors += "LAPS enumeration failed"
        }
    }
    else {
        Write-MSADPTLog -Message "Skipping LAPS configuration enumeration for $DCName." -Level 'INFO'
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

Write-MSADPTLog -Message "MSADPT_enumerate_dc2.ps1 completed." -Level 'INFO'
