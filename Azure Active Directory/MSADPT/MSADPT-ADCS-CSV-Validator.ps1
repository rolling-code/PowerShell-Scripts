# MSADPT-ADCS-CSV-Validator.ps1
#
# Description:
#   Reads the CSV output produced by MSADPT_audit_adcs_esc1_esc16.ps1 and
#   processes unique FAIL findings.
#
#   For ACL-based findings, the script performs read-only Active Directory
#   validation by inspecting object security descriptors. For findings that
#   require CA-local, IIS, registry, or environment-specific review, the script
#   prints operator guidance and suggested manual validation steps.
#
#   This script does not exploit AD CS misconfigurations, request certificates,
#   modify templates, change ACLs, write registry values, or alter CA settings.
#
# Validation behavior:
#   - ESC2  : Validates dangerous broad-principal write rights on certificate templates.
#   - ESC4  : Validates dangerous broad-principal write rights on CA enrollment service objects.
#   - ESC13 : Validates dangerous broad-principal write rights on DC-auth-like templates.
#   - ESC14 : Validates dangerous broad-principal write rights on critical PKI objects.
#   - Other FAIL findings may emit manual validation guidance where implemented.
#
# Requirements:
#   - PowerShell 7.0+
#   - ActiveDirectory PowerShell module / RSAT AD tools
#   - MSADPT.Helpers.psm1 in the same directory as this script
#   - Explicit DirectoryServer and Credential parameters
#
# Usage:
#   $cred = Get-Credential
#
#   .\MSADPT-ADCS-CSV-Validator.ps1 `
#       -InputCSVPath "C:\temp\MSADPT_Output\ADCS\MSADPT_ADCS_ESC_Audit_20260512_101500.csv" `
#       -DomainFQDN "foo.bar" `
#       -DirectoryServer "DC1.foo.bar" `
#       -Credential $cred
#
# Notes:
#   - DomainFQDN is used for operator context and reporting.
#   - DirectoryServer is used as the explicit AD query target.
#   - Credential is used for all Active Directory validation queries.
#   - The script prompts before validating each unique FAIL finding.

param(
    [Parameter(Mandatory)]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
            throw "Input CSV file '$_' does not exist."
        }
        $true
    })]
    [string]$InputCSVPath,

	[Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainFQDN,
	
	[Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
    [string]$DirectoryServer,

	[Parameter(Mandatory)]
	[ValidateNotNull()]
	[PSCredential]$Credential
)

$helpersModulePath = Join-Path $PSScriptRoot 'MSADPT.Helpers.psm1'

if (-not (Test-Path -LiteralPath $helpersModulePath -PathType Leaf)) {
    Write-Error "Required helper module not found at '$helpersModulePath'. Aborting."
    exit 1
}

Import-Module $helpersModulePath -Force -ErrorAction Stop

Write-MSADPTLog -Message "MSADPT-ADCS-CSV-Validator.ps1 started for domain: $DomainFQDN" -Level 'INFO'
Write-MSADPTLog -Message "Input CSV file: $InputCSVPath" -Level 'INFO'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-MSADPTLog -Message "Required module 'ActiveDirectory' is not available. Install RSAT Active Directory tools and rerun." -Level 'ERROR'
    exit 1
}

if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-MSADPTLog -Message "Imported module 'ActiveDirectory'." -Level 'INFO'
}

function Resolve-CertificateTemplateDN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ObjectName,

        [Parameter(Mandatory)]
        [string]$ConfigNC,

        [Parameter(Mandatory)]
        [string]$DirectoryServer,

        [Parameter()]
        [PSCredential]$Credential
    )

    if ([string]::IsNullOrWhiteSpace($ConfigNC)) {
        throw "ConfigNC is empty. Cannot resolve certificate template DN."
    }

    # If ObjectName is already a DN, return it.
    if ($ObjectName -like 'CN=*') {
        return $ObjectName
    }

    # Extract template CN from friendly label:
    # "Domain Controller (DomainController)" -> "DomainController"
    $templateCN = $null

    if ($ObjectName -match '\(([^()]+)\)\s*$') {
        $templateCN = $Matches[1]
    }
    else {
        $templateCN = $ObjectName
    }

    $templatesBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

    $splat = @{
        SearchBase  = $templatesBase
        LDAPFilter  = "(&(objectClass=pKICertificateTemplate)(cn=$templateCN))"
        Server      = $DirectoryServer
        ErrorAction = 'Stop'
    }

    if ($null -ne $Credential) {
        $splat.Credential = $Credential
    }

    $template = Get-ADObject @splat

    if ($null -eq $template) {
        throw "Certificate template '$templateCN' was not found under '$templatesBase'."
    }

    return [string]$template.DistinguishedName
}

# --- Helper function to test for dangerous write ACLs on AD Objects ---
function Test-DangerousWriteACL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ObjectDN,

        [Parameter(Mandatory)]
        [string]$CheckType,

        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [Parameter(Mandatory)]
        [string]$DirectoryServer,

        [Parameter(Mandatory)]
        [scriptblock]$LogFunction
    )

    & $LogFunction "PROMPT: Inspecting ACL for $CheckType at DN: $ObjectDN" "INFO"
    & $LogFunction "Purpose: Validate if broad principals have dangerous write rights on this critical object." "INFO"

    try {
        $adObject = Get-ADObject `
            -Identity $ObjectDN `
            -Properties nTSecurityDescriptor `
            -Server $DirectoryServer `
            -Credential $Credential `
            -ErrorAction Stop

        $aces = @($adObject.nTSecurityDescriptor.Access)

        $dangerousAces = foreach ($ace in $aces) {
            if ($ace.AccessControlType -ne 'Allow') {
                continue
            }

            $principal = [string]$ace.IdentityReference
            $rights    = $ace.ActiveDirectoryRights

            $isBroadPrincipal =
                $principal -match 'Authenticated Users' -or
                $principal -match 'Everyone' -or
                $principal -match 'Domain Users' -or
                $principal -match 'Domain Computers' -or
                $principal -match 'BUILTIN\\Users'

            if (-not $isBroadPrincipal) {
                continue
            }

            $hasDangerousWrite =
                (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0) -or
                (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -ne 0) -or
                (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -ne 0) -or
                (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -ne 0) -or
                (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne 0)

            if ($hasDangerousWrite) {
                $ace
            }
        }

        $dangerousAces = @($dangerousAces)

        if ($dangerousAces.Count -gt 0) {
            & $LogFunction "CONFIRMED: Dangerous broad-principal write ACE(s) found on '$ObjectDN'." "FAIL"

            foreach ($ace in $dangerousAces) {
                & $LogFunction "ACE: $($ace.IdentityReference) / Rights: $($ace.ActiveDirectoryRights) / Type: $($ace.AccessControlType)" "FAIL"
            }

            return $true
        }
        else {
            & $LogFunction "No dangerous broad-principal write ACEs found on '$ObjectDN'." "PASS"
            return $false
        }
    }
    catch {
        & $LogFunction "ERROR: Failed to retrieve or parse ACL for '$ObjectDN'. Message: $($_.Exception.Message)" "ERROR"
        & $LogFunction "This might be a false negative or an access issue. Manual verification of '$ObjectDN' is strongly recommended." "WARNING"
        return $false
    }
}

# --- Read and Filter Input CSV ---
Write-MSADPTLog -Message "`nReading ADCS audit results from '$InputCSVPath'..." -Level 'INFO'
try {
    $AuditResults = Import-Csv -Path $InputCSVPath
    Write-MSADPTLog -Message "Successfully loaded $($AuditResults.Count) entries from CSV." -Level 'INFO'
}
catch {
    Write-MSADPTLog -Message "ERROR: Failed to read input CSV '$InputCSVPath'. Ensure the path is correct and the file is accessible. Message: $($_.Exception.Message)" -Level 'ERROR'
    Exit
}

if (-not $AuditResults -or @($AuditResults).Count -eq 0) {
    Write-MSADPTLog -Message "Input CSV contains no rows. Exiting." -Level 'WARNING'
    exit 0
}


$requiredColumns = @('ESC', 'Status', 'ObjectName', 'Reason', 'Scope')
$actualColumns = @($AuditResults[0].PSObject.Properties.Name)

foreach ($column in $requiredColumns) {
    if ($actualColumns -notcontains $column) {
        Write-MSADPTLog -Message "Input CSV is missing required column '$column'. Aborting." -Level 'ERROR'
        exit 1
    }
}


$LogFunction = {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [string]$Level = 'INFO'
    )

    Write-MSADPTLog -Message $Message -Level $Level
}

function Resolve-CAEnrollmentServiceDN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ObjectName,

        [Parameter(Mandatory)]
        [string]$ConfigNC,

        [Parameter(Mandatory)]
        [string]$DirectoryServer,

        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )

    if ($ObjectName -like 'CN=*') {
        return $ObjectName
    }

    $caName = $ObjectName

    if ($ObjectName -match '\(([^()]+)\)\s*$') {
        $caName = $Matches[1]
    }

    $enrollmentBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"

    $splat = @{
        SearchBase  = $enrollmentBase
        LDAPFilter  = "(&(objectClass=pKIEnrollmentService)(cn=$caName))"
        Server      = $DirectoryServer
        Credential  = $Credential
        ErrorAction = 'Stop'
    }

    $ca = Get-ADObject @splat

    if ($null -eq $ca) {
        throw "CA enrollment service '$caName' was not found under '$enrollmentBase'."
    }

    return [string]$ca.DistinguishedName
}

# ---------------------------------------------------------------------
# Resolve Configuration Naming Context
# ---------------------------------------------------------------------
try {
    Write-MSADPTLog -Message "Resolving Configuration Naming Context from DirectoryServer '$DirectoryServer'." -Level 'INFO'

    $rootDSE = Test-MSADPTADConnectivity -Credential $Credential -AdServer $DirectoryServer
	if (-not $rootDSE) {
		Write-MSADPTLog -Message "Active Directory connectivity pre-flight failed. Aborting." -Level 'ERROR'
		exit 1
	}

	$ConfigNC = [string]$rootDSE.configurationNamingContext

    if ([string]::IsNullOrWhiteSpace($ConfigNC)) {
        throw "Get-ADRootDSE returned an empty configurationNamingContext."
    }

    Write-MSADPTLog -Message "Configuration Naming Context resolved: $ConfigNC" -Level 'INFO'
}
catch {
    Write-MSADPTLog -Message "ERROR: Failed to resolve Configuration Naming Context from DirectoryServer '$DirectoryServer'. Message: $($_.Exception.Message)" -Level 'ERROR'
    exit 1
}

# Filter ONLY for FAIL items, and then deduplicate by grouping on unique ESC, ObjectName, and Reason.
# The audit tool produces the full DN in ObjectName, which makes it unique already for specific instances.
# Grouping by ESC and ObjectName is sufficient for deduplication for the purpose of validation.
$UniqueFailures = $AuditResults | Where-Object { $_.Status -eq 'FAIL' } | Group-Object -Property ESC, ObjectName


# --- Process Unique FAIL Findings ---
Write-MSADPTLog -Message "`n--- Initiating Targeted ADCS Vulnerability Validation ---" -Level 'INFO'

if ([string]::IsNullOrWhiteSpace($ConfigNC)) {
    throw "ConfigNC was not initialized before validation loop. Check Get-ADRootDSE initialization."
}

if ($null -eq $LogFunction) {
    throw "LogFunction is null. Define `$LogFunction before calling Test-DangerousWriteACL."
}

foreach ($FailureGroup in $UniqueFailures) {
	
  # Use the first CSV row in the group as the representative finding.
    # Do NOT use $FailureGroup.Name. GroupInfo.Name is a string, not an object.
    $Finding = $FailureGroup.Group[0]

    $EscType        = [string]$Finding.ESC
    $ObjectName     = [string]$Finding.ObjectName
    $OriginalReason = [string]$Finding.Reason
    $Scope          = [string]$Finding.Scope

    Write-MSADPTLog -Message "`n--- Processing Unique Finding: [$EscType] - $Scope ($ObjectName) ---" -Level 'INFO'
    Write-MSADPTLog -Message "Original Audit Reason: $OriginalReason" -Level 'INFO'
    
	if (-not (Prompt-User -PromptText "Proceed to validate [$EscType] for '$Scope' ('$ObjectName')?")) {
		Write-MSADPTLog -Message "Validation for [$EscType] on '$Scope' ('$ObjectName') skipped by user." -Level 'INFO'
		continue
	}

    switch ($EscType) {
		'ESC1' {
			Write-MSADPTLog -Message "Manual validation for ESC1:" -Level 'INFO'
			Write-MSADPTLog -Message "Review the certificate template '$ObjectName' for enrollee-supplied subject, auth-capable EKUs, broad enrollment, and missing issuance controls." -Level 'INFO'
		}

		'ESC2' {
			$TemplateDN = Resolve-CertificateTemplateDN `
				-ObjectName $ObjectName `
				-ConfigNC $ConfigNC `
				-DirectoryServer $DirectoryServer `
				-Credential $Credential

			Write-MSADPTLog -Message "Validating ESC2: Broad principal has dangerous write rights on the certificate template." -Level 'INFO'

			Test-DangerousWriteACL `
				-ObjectDN $TemplateDN `
				-CheckType "ESC2 Certificate Template ($ObjectName)" `
				-Credential $Credential `
				-DirectoryServer $DirectoryServer `
				-LogFunction $LogFunction
		}
		'ESC3' {
			Write-MSADPTLog -Message "Manual validation for ESC3:" -Level 'INFO'
			Write-MSADPTLog -Message "Review template '$ObjectName' for Enrollment Agent EKU, broad enrollment permissions, and missing issuance controls such as manager approval or authorized signatures." -Level 'INFO'
		}

		'ESC4' {
			$CaEnrollmentServiceDN = Resolve-CAEnrollmentServiceDN `
				-ObjectName $ObjectName `
				-ConfigNC $ConfigNC `
				-DirectoryServer $DirectoryServer `
				-Credential $Credential

			Write-MSADPTLog -Message "Validating ESC4: Broad principal has dangerous write rights on the CA enrollment service object." -Level 'INFO'

			Test-DangerousWriteACL `
				-ObjectDN $CaEnrollmentServiceDN `
				-CheckType "ESC4 CA Enrollment Service ($ObjectName)" `
				-Credential $Credential `
				-DirectoryServer $DirectoryServer `
				-LogFunction $LogFunction
		}
	   'ESC6' {
			Write-MSADPTLog -Message "Manual validation for ESC6:" -Level 'INFO'
			Write-MSADPTLog -Message "Run on the CA server: certutil -getreg CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags" -Level 'REVIEW'
			Write-MSADPTLog -Message "Check whether EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled." -Level 'INFO'
		}
		'ESC8' {
			Write-MSADPTLog -Message "Manual validation for ESC8:" -Level 'INFO'
			Write-MSADPTLog -Message "Review AD CS Web Enrollment/IIS exposure for '$ObjectName'. Check /certsrv/ HTTP/HTTPS reachability, NTLM, and EPA settings." -Level 'REVIEW'
		}
		'ESC9' {
			Write-MSADPTLog -Message "Manual validation for ESC9:" -Level 'INFO'
			Write-MSADPTLog -Message "Review template '$ObjectName' for CT_FLAG_NO_SECURITY_EXTENSION and authentication-capable EKUs. Confirm whether SID security extension is disabled." -Level 'INFO'
		}
		'ESC10' {
			Write-MSADPTLog -Message "Manual validation for ESC10:" -Level 'INFO'
			Write-MSADPTLog -Message "Review DC certificate mapping posture, StrongCertificateBindingEnforcement, certificate renewal behavior, and weak/legacy mapping paths for '$ObjectName'." -Level 'INFO'
		}
		'ESC12' {
			Write-MSADPTLog -Message "Manual validation for ESC12:" -Level 'INFO'
			Write-MSADPTLog -Message "Review DC-auth-like template '$ObjectName' for enrollee-supplied subject, broad enrollment permissions, and whether the template can be used for domain controller authentication." -Level 'INFO'
		}
		'ESC13' {
			$TemplateDN = Resolve-CertificateTemplateDN `
				-ObjectName $ObjectName `
				-ConfigNC $ConfigNC `
				-DirectoryServer $DirectoryServer `
				-Credential $Credential

			Write-MSADPTLog -Message "Validating ESC13: DC-auth-like template has broad dangerous write rights." -Level 'INFO'

			Test-DangerousWriteACL `
				-ObjectDN $TemplateDN `
				-CheckType "ESC13 DC-Auth Template ($ObjectName)" `
				-Credential $Credential `
				-DirectoryServer $DirectoryServer `
				-LogFunction $LogFunction
		}
		'ESC14' {
			$FriendlyName = ($ObjectName.Split(',') | Select-Object -First 1) -replace "CN=",""

			Write-MSADPTLog -Message "Validating ESC14: Broad principal has dangerous write rights on a critical PKI object." -Level 'INFO'

			Test-DangerousWriteACL `
				-DirectoryServer $DirectoryServer `
				-ObjectDN $ObjectName `
				-CheckType "ESC14 PKI Object ($FriendlyName)" `
				-Credential $Credential `
				-LogFunction $LogFunction
		}
		'ESC16' {
			Write-MSADPTLog -Message "Manual validation for ESC16:" -Level 'INFO'
			Write-MSADPTLog -Message "Run on the CA server: certutil -getreg CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\DisableExtensionList" -Level 'INFO'
		}

        default {
            Write-MSADPTLog -Message "WARNING: Unhandled ESC type '$EscType' found in CSV for '$ObjectName'. No specific validation logic implemented." -Level 'WARNING'
        }
    }
}

Write-MSADPTLog -Message "`n--- Targeted ADCS Vulnerability Validation Complete ---" -Level 'INFO'
Write-MSADPTLog -Message "MSADPT-ADCS-CSV-Validator.ps1 finished. Review the highlighted entries for confirmed vulnerabilities." -Level 'INFO'
