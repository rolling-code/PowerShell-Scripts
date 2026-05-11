# Requires -Version 7.0

<#
.SYNOPSIS
    MSADPT_audit_adcs_esc1_esc16.ps1 - Audits an AD CS deployment for likely
    exposures associated with ESC1 through ESC16.

.DESCRIPTION
    This script performs a defensive, configuration-focused audit of an enterprise
    AD CS deployment. It enumerates:
      - Enterprise Certification Authorities (CAs)
      - Published certificate templates
      - Relevant PKI objects in the Configuration partition
      - Template ACLs and selected PKI object ACLs
      - Selected CA registry flags (best effort)
      - Selected DC certificate-mapping posture indicators (best effort)
      - Web enrollment exposure indicators (best effort)

    The script emits structured findings with one of:
      - PASS   : No direct exposure indicator was observed for the tested control
      - FAIL   : A likely exposure indicator was observed
      - REVIEW : The control is partially checked, environment-dependent, or could
                 not be fully validated programmatically

    IMPORTANT:
      - This script does not exploit anything.
      - It does not request or forge certificates.
      - It does not change templates, ACLs, registry keys, or CA settings.
      - PASS means "no direct exposure indicator observed by this script", not an
        absolute guarantee of safety.

.PARAMETER OutputBaseDir
    Directory where CSV and log outputs are written.
    Defaults to '.\MSADPT_Output' under the current working directory.

.PARAMETER IncludeUnpublishedTemplates
    When set, evaluates all templates in AD. By default, the script focuses on
    templates currently published by at least one enterprise CA.

.PARAMETER SkipRemoteChecks
    When set, skips best-effort remote registry and web endpoint checks against
    CA servers and DCs.

.PARAMETER DirectoryServer
    domain controller / directory server to use for Active Directory
    queries. This parameter is strongly recommended when running from a machine
    that is not domain joined.

.PARAMETER Credential
    credential to use for Active Directory queries and remote checks.

.OUTPUTS
    - MSADPT_ADCS_ESC_Audit_<timestamp>.csv
    - MSADPT_ADCS_ESC_Audit_Log_<timestamp>.txt

.EXAMPLE
    .\MSADPT_audit_adcs_esc1_esc16.ps1 `
        -OutputBaseDir "C:\temp\MSADPT_Output\ADCS"

    Runs the AD CS audit from a domain-joined system using the current user's
    domain context.

.EXAMPLE
    $cred = Get-Credential

    .\MSADPT_audit_adcs_esc1_esc16.ps1 `
        -DirectoryServer "dc01.contoso.local" `
        -Credential $cred `
        -OutputBaseDir "C:\temp\MSADPT_Output\ADCS"

    Runs the AD CS audit from a non-domain-joined system by explicitly targeting
    a domain controller and supplying credentials.
#>

param(
    [Parameter(Mandatory)]
    [string]$OutputBaseDir,

    [Parameter(Mandatory)]
    [switch]$IncludeUnpublishedTemplates,

    [Parameter(Mandatory)]
    [switch]$SkipRemoteChecks,

    [Parameter(Mandatory)]
    [string]$DirectoryServer,

    [Parameter(Mandatory)]
    [PSCredential]$Credential
)

# ---------------------------------------------------------------------
# Import helper module from the same folder as the script
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
$ScriptStartTime = Get-Date -Format "yyyyMMdd_HHmmss"

if (-not (Test-Path -LiteralPath $OutputBaseDir -PathType Container)) {
    New-Item -Path $OutputBaseDir -ItemType Directory -Force | Out-Null
}
$OutputBaseDir = (Resolve-Path -LiteralPath $OutputBaseDir).Path

$LogFilePath = Join-Path $OutputBaseDir "MSADPT_ADCS_ESC_Audit_Log_$ScriptStartTime.txt"

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO','WARNING','ERROR','PASS','FAIL','REVIEW')]
        [string]$Level = 'INFO'
    )

    Write-MSADPTLog -Message $Message -Level $Level -LogFilePath $LogFilePath
}

Write-Log -Message "Starting AD CS ESC audit." -Level 'INFO'
Write-Log -Message "Output directory: $OutputBaseDir" -Level 'INFO'
Write-Log -Message "IncludeUnpublishedTemplates: $IncludeUnpublishedTemplates" -Level 'INFO'
Write-Log -Message "SkipRemoteChecks: $SkipRemoteChecks" -Level 'INFO'

if ([string]::IsNullOrWhiteSpace($DirectoryServer)) {
    Write-Log -Message "DirectoryServer was not specified. Automatic AD discovery will be attempted from local machine context." -Level 'INFO'
    Write-Log -Message "If this machine is not domain joined, rerun with -DirectoryServer <dc.fqdn>." -Level 'INFO'
}
else {
    Write-Log -Message "Using explicit DirectoryServer: $DirectoryServer" -Level 'INFO'
}

if ($null -ne $Credential) {
    Write-Log -Message "Explicit credential supplied for AD enumeration and remote checks." -Level 'INFO'
}

# ---------------------------------------------------------------------
# Module checks
# ---------------------------------------------------------------------
$RequiredModules = @('ActiveDirectory')

foreach ($module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Log -Message "Required module '$module' is not available. Aborting." -Level 'ERROR'
        exit 1
    }

    if (-not (Get-Module -Name $module)) {
        Import-Module $module -ErrorAction Stop
        Write-Log -Message "Imported module '$module'." -Level 'INFO'
    }
}

# ---------------------------------------------------------------------
# Constants / GUIDs / Flags
# ---------------------------------------------------------------------
$EnrollGuid     = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$AutoEnrollGuid = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

$CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
$CT_FLAG_NO_SECURITY_EXTENSION     = 0x00080000
$CT_FLAG_PEND_ALL_REQUESTS         = 0x00000002

$EDITF_ATTRIBUTESUBJECTALTNAME2    = 0x00040000

$SidSecurityExtensionOid = '1.3.6.1.4.1.311.25.2'

$EkuClientAuth          = '1.3.6.1.5.5.7.3.2'
$EkuSmartCardLogon      = '1.3.6.1.4.1.311.20.2.2'
$EkuPkinitClientAuth    = '1.3.6.1.5.2.3.4'
$EkuAnyPurpose          = '2.5.29.37.0'
$EkuEnrollmentAgent     = '1.3.6.1.4.1.311.20.2.1'

# ---------------------------------------------------------------------
# Helper: broad / low-privilege principal heuristics
# ---------------------------------------------------------------------
function Test-IsBroadPrincipal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IdentityReference
    )

    $broadPatterns = @(
        'Everyone',
        'NT AUTHORITY\Authenticated Users',
        'Authenticated Users',
        'BUILTIN\Users',
        '\Domain Users',
        '\Domain Computers',
        '\Users'
    )

    foreach ($pattern in $broadPatterns) {
        if ($IdentityReference -like "*$pattern") {
            return $true
        }
    }

    return $false
}

# ---------------------------------------------------------------------
# Helper: read AD object ACLs without relying on AD:\ provider context
# ---------------------------------------------------------------------
function Get-DirectoryObjectAclEntries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    try {
        $ldapPath = if ([string]::IsNullOrWhiteSpace($DirectoryServer)) {
            "LDAP://$DistinguishedName"
        }
        else {
            "LDAP://$DirectoryServer/$DistinguishedName"
        }

        if ($null -ne $Credential) {
            $netCred = $Credential.GetNetworkCredential()
            $entry = New-Object System.DirectoryServices.DirectoryEntry(
                $ldapPath,
                $netCred.UserName,
                $netCred.Password
            )
        }
        else {
            $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }

        $null = $entry.RefreshCache()
        $acl = $entry.ObjectSecurity

        return @($acl.Access)
    }
    catch {
        Write-Log -Message "Failed to read ACL on '$DistinguishedName': $($_.Exception.Message)" -Level 'WARNING'
        return @()
    }
}

function Get-AclSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    $entries = Get-DirectoryObjectAclEntries -DistinguishedName $DistinguishedName

    $summary = [ordered]@{
        BroadEnroll          = $false
        BroadAutoEnroll      = $false
        BroadDangerousWrite  = $false
        BroadDangerousAceIds = @()
    }

    foreach ($ace in $entries) {
        if ($ace.AccessControlType -ne 'Allow') {
            continue
        }

        $principal = $ace.IdentityReference.Value

        if (-not (Test-IsBroadPrincipal -IdentityReference $principal)) {
            continue
        }

        $rights = $ace.ActiveDirectoryRights

        if (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0) {
            if ($ace.ObjectType -eq $EnrollGuid) {
                $summary.BroadEnroll = $true
                $summary.BroadDangerousAceIds += $principal
            }
            elseif ($ace.ObjectType -eq $AutoEnrollGuid) {
                $summary.BroadAutoEnroll = $true
                $summary.BroadDangerousAceIds += $principal
            }
        }

        if (
            (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)   -ne 0) -or
            (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)  -ne 0) -or
            (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)     -ne 0) -or
            (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)    -ne 0) -or
            (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne 0)
        ) {
            $summary.BroadDangerousWrite = $true
            $summary.BroadDangerousAceIds += $principal
        }
    }

    $summary.BroadDangerousAceIds = @($summary.BroadDangerousAceIds | Sort-Object -Unique)
    return [PSCustomObject]$summary
}

# ---------------------------------------------------------------------
# Helper: template interpretation
# ---------------------------------------------------------------------
function Test-TemplateSuppliesSubject {
    [CmdletBinding()]
    param([int]$NameFlag)

    return (($NameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0)
}

function Test-TemplateNoSecurityExtension {
    [CmdletBinding()]
    param([int]$NameFlag)

    return (($NameFlag -band $CT_FLAG_NO_SECURITY_EXTENSION) -ne 0)
}

function Test-TemplateManagerApproval {
    [CmdletBinding()]
    param([int]$EnrollmentFlag)

    return (($EnrollmentFlag -band $CT_FLAG_PEND_ALL_REQUESTS) -ne 0)
}

function Test-TemplateHasAuthEku {
    [CmdletBinding()]
    param([object]$Ekus)

    $ekuList = @()
    if ($null -ne $Ekus) {
        $ekuList = @($Ekus)
    }

    if ($ekuList.Count -eq 0) {
        return $true
    }

    $authEkus = @(
        $EkuClientAuth,
        $EkuSmartCardLogon,
        $EkuPkinitClientAuth,
        $EkuAnyPurpose
    )

    return (@($ekuList | Where-Object { $authEkus -contains $_ }).Count -gt 0)
}

function Test-TemplateHasEnrollmentAgentEku {
    [CmdletBinding()]
    param([object]$Ekus)

    $ekuList = @()
    if ($null -ne $Ekus) {
        $ekuList = @($Ekus)
    }

    return (@($ekuList | Where-Object { $_ -eq $EkuEnrollmentAgent }).Count -gt 0)
}

function Test-TemplateLooksLikeDcAuth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Template
    )

    $nameCandidates = @($Template.Name, $Template.displayName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($candidate in $nameCandidates) {
        if ($candidate -match 'Domain\s*Controller' -or $candidate -match 'Kerberos\s*Authentication') {
            return $true
        }
    }

    return $false
}

# ---------------------------------------------------------------------
# Finding collector
# ---------------------------------------------------------------------
$Findings = New-Object System.Collections.Generic.List[object]

function Add-ESCFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Esc,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter()][string]$Evidence = '',
        [Parameter()][string]$Recommendation = ''
    )

    $row = [PSCustomObject]@{
        Timestamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ESC            = $Esc
        Status         = $Status
        Scope          = $Scope
        ObjectName     = $ObjectName
        Reason         = $Reason
        Evidence       = $Evidence
        Recommendation = $Recommendation
    }

    $script:Findings.Add($row)
    Write-Log -Message "$Esc [$Status] $ObjectName - $Reason" -Level $Status
}

# ---------------------------------------------------------------------
# Build AD cmdlet splat using imported helper
# ---------------------------------------------------------------------
$adSplat = New-MSADPTAdCommandSplat -Server $DirectoryServer -Credential $Credential

# ---------------------------------------------------------------------
# Enumerate AD CS / PKI objects
# ---------------------------------------------------------------------
try {
    $rootDse = Get-ADRootDSE @adSplat -ErrorAction Stop
    $configNc = $rootDse.configurationNamingContext

    $templatesBase   = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNc"
    $enrollmentBase  = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNc"
    $pkiservicesBase = "CN=Public Key Services,CN=Services,$configNc"

    $templateProps = @(
        'displayName',
        'msPKI-Certificate-Name-Flag',
        'msPKI-Enrollment-Flag',
        'msPKI-RA-Signature',
        'pKIExtendedKeyUsage',
        'flags',
        'msPKI-Template-Schema-Version'
    )

    $caProps = @(
        'dNSHostName',
        'displayName',
        'certificateTemplates',
        'flags'
    )

    $caObjects = @(
        Get-ADObject @adSplat `
            -SearchBase $enrollmentBase `
            -LDAPFilter '(objectClass=pKIEnrollmentService)' `
            -Properties $caProps `
            -ErrorAction Stop
    )

    $templateObjects = @(
        Get-ADObject @adSplat `
            -SearchBase $templatesBase `
            -LDAPFilter '(objectClass=pKICertificateTemplate)' `
            -Properties $templateProps `
            -ErrorAction Stop
    )

    Write-Log -Message "Found $($caObjects.Count) enterprise CA object(s)." -Level 'INFO'
    Write-Log -Message "Found $($templateObjects.Count) certificate template object(s)." -Level 'INFO'
}
catch {
    Write-Log -Message "Failed to enumerate AD CS objects from AD: $($_.Exception.Message)" -Level 'ERROR'
    Write-Log -Message "If this machine is not domain joined, rerun with -DirectoryServer <dc.fqdn> and optionally -Credential." -Level 'ERROR'
    exit 1
}

# ---------------------------------------------------------------------
# Build published template name set
# ---------------------------------------------------------------------
$publishedTemplateNames = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)

foreach ($ca in $caObjects) {
    foreach ($tpl in @($ca.certificateTemplates)) {
        [void]$publishedTemplateNames.Add([string]$tpl)
    }
}

# ---------------------------------------------------------------------
# PKI object ACL checks
# ---------------------------------------------------------------------
$pkiCriticalDns = @(
    $enrollmentBase,
    "CN=NTAuthCertificates,$pkiservicesBase",
    "CN=AIA,$pkiservicesBase",
    "CN=Certification Authorities,$pkiservicesBase"
)

foreach ($dn in $pkiCriticalDns) {
    $aclSummary = Get-AclSummary -DistinguishedName $dn

    if ($aclSummary.BroadDangerousWrite) {
        Add-ESCFinding -Esc 'ESC14' -Status 'FAIL' -Scope 'PKI Object ACL' -ObjectName $dn `
            -Reason 'Broad principal has dangerous write rights on a critical PKI object.' `
            -Evidence ($aclSummary.BroadDangerousAceIds -join '; ') `
            -Recommendation 'Restrict GenericWrite/GenericAll/WriteDacl/WriteOwner/WriteProperty on PKI objects to dedicated Tier 0 PKI admins only.'
    }
    else {
        Add-ESCFinding -Esc 'ESC14' -Status 'PASS' -Scope 'PKI Object ACL' -ObjectName $dn `
            -Reason 'No broad dangerous write rights observed on this critical PKI object.' `
            -Recommendation 'Continue periodic ACL review of PKI objects.'
    }
}

# ---------------------------------------------------------------------
# Template-level checks
# ---------------------------------------------------------------------
foreach ($template in $templateObjects) {
    $templateName = [string]$template.Name
    $displayName  = [string]$template.displayName

    $isPublished = $publishedTemplateNames.Contains($templateName)
    if (-not $IncludeUnpublishedTemplates -and -not $isPublished) {
        continue
    }

    $nameFlag       = $template.'msPKI-Certificate-Name-Flag' | Select-Object -First 1
    $enrollmentFlag = $template.'msPKI-Enrollment-Flag' | Select-Object -First 1

    $raSigCount = 0
    if ($null -ne $template.'msPKI-RA-Signature') {
        $raSigCount = [int]$template.'msPKI-RA-Signature'
    }

    $ekus            = @($template.pKIExtendedKeyUsage)
    $suppliesSubject = Test-TemplateSuppliesSubject -NameFlag $nameFlag
    $noSecExt        = Test-TemplateNoSecurityExtension -NameFlag $nameFlag
    $managerApproval = Test-TemplateManagerApproval -EnrollmentFlag $enrollmentFlag
    $hasAuthEku      = Test-TemplateHasAuthEku -Ekus $ekus
    $hasEaEku        = Test-TemplateHasEnrollmentAgentEku -Ekus $ekus
    $looksLikeDcAuth = Test-TemplateLooksLikeDcAuth -Template $template

    $aclSummary = Get-AclSummary -DistinguishedName $template.DistinguishedName

    $templateLabel = if ([string]::IsNullOrWhiteSpace($displayName)) {
        $templateName
    }
    else {
        "$displayName ($templateName)"
    }

    # ESC1
    if ($isPublished -and $suppliesSubject -and $hasAuthEku -and $aclSummary.BroadEnroll -and (-not $managerApproval) -and ($raSigCount -eq 0)) {
        Add-ESCFinding -Esc 'ESC1' -Status 'FAIL' -Scope 'Template' -ObjectName $templateLabel `
            -Reason 'Published template allows enrollee-supplied subject on an auth-capable template with broad enrollment and no issuance gates.' `
            -Evidence "NameFlag=$nameFlag; EnrollmentFlag=$enrollmentFlag; EKUs=$($ekus -join ','); BroadEnroll=$($aclSummary.BroadEnroll)" `
            -Recommendation 'Disable Supply in request, restrict enrollment, and/or require manager approval / authorized signatures.'
    }
    else {
        Add-ESCFinding -Esc 'ESC1' -Status 'PASS' -Scope 'Template' -ObjectName $templateLabel `
            -Reason 'Direct ESC1 indicator set not observed on this template.' `
            -Evidence "Published=$isPublished; SuppliesSubject=$suppliesSubject; HasAuthEku=$hasAuthEku; BroadEnroll=$($aclSummary.BroadEnroll)" `
            -Recommendation 'Review periodically for template drift.'
    }

    # ESC2
    if ($aclSummary.BroadDangerousWrite) {
        Add-ESCFinding -Esc 'ESC2' -Status 'FAIL' -Scope 'Template ACL' -ObjectName $templateLabel `
            -Reason 'Broad principal has dangerous write rights on the certificate template.' `
            -Evidence ($aclSummary.BroadDangerousAceIds -join '; ') `
            -Recommendation 'Restrict template modification rights to dedicated PKI admins.'
    }
    else {
        Add-ESCFinding -Esc 'ESC2' -Status 'PASS' -Scope 'Template ACL' -ObjectName $templateLabel `
            -Reason 'No broad dangerous write rights observed on the template.' `
            -Recommendation 'Continue periodic ACL review.'
    }

    # ESC3
    if ($isPublished -and $hasEaEku -and $aclSummary.BroadEnroll -and (-not $managerApproval) -and ($raSigCount -eq 0)) {
        Add-ESCFinding -Esc 'ESC3' -Status 'FAIL' -Scope 'Template' -ObjectName $templateLabel `
            -Reason 'Published Enrollment Agent-capable template is broadly enrollable without issuance gates.' `
            -Evidence "EKUs=$($ekus -join ','); BroadEnroll=$($aclSummary.BroadEnroll); ManagerApproval=$managerApproval; RASignatures=$raSigCount" `
            -Recommendation 'Restrict enrollment and require issuance controls for request-agent templates.'
    }
    else {
        Add-ESCFinding -Esc 'ESC3' -Status 'PASS' -Scope 'Template' -ObjectName $templateLabel `
            -Reason 'Direct ESC3 indicator set not observed on this template.' `
            -Recommendation 'Review Enrollment Agent templates separately during PKI governance reviews.'
    }

    # ESC9
    if ($isPublished -and $noSecExt -and $hasAuthEku -and $aclSummary.BroadEnroll) {
        Add-ESCFinding -Esc 'ESC9' -Status 'FAIL' -Scope 'Template' -ObjectName $templateLabel `
            -Reason 'Published auth-capable template disables the SID security extension and is broadly enrollable.' `
            -Evidence "NameFlag=$nameFlag; BroadEnroll=$($aclSummary.BroadEnroll); EKUs=$($ekus -join ',')" `
            -Recommendation 'Remove CT_FLAG_NO_SECURITY_EXTENSION and restrict enrollment.'
    }
    else {
        Add-ESCFinding -Esc 'ESC9' -Status 'PASS' -Scope 'Template' -ObjectName $templateLabel `
            -Reason 'Direct ESC9 indicator set not observed on this template.' `
            -Recommendation 'Review strong mapping / SID extension posture periodically.'
    }

    # ESC10
    Add-ESCFinding -Esc 'ESC10' -Status 'REVIEW' -Scope 'Template / Mapping' -ObjectName $templateLabel `
        -Reason 'ESC10-style renewal / weak certificate mapping scenarios are environment-dependent and not fully inferable from template attributes alone.' `
        -Evidence "SuppliesSubject=$suppliesSubject; HasAuthEku=$hasAuthEku; NoSecurityExtension=$noSecExt" `
        -Recommendation 'Review certificate renewal behavior, mapping methods, and affected auth paths manually.'

    # ESC12
    if ($isPublished -and $looksLikeDcAuth -and $suppliesSubject -and $aclSummary.BroadEnroll) {
        Add-ESCFinding -Esc 'ESC12' -Status 'FAIL' -Scope 'Template' -ObjectName $templateLabel `
            -Reason 'DC-auth-like template appears to allow enrollee-supplied subject and broad enrollment.' `
            -Evidence "TemplateName=$templateName; DisplayName=$displayName; SuppliesSubject=$suppliesSubject; BroadEnroll=$($aclSummary.BroadEnroll)" `
            -Recommendation 'Remove Supply in request and restrict enrollment on DC-authentication templates.'
    }
    else {
        Add-ESCFinding -Esc 'ESC12' -Status 'PASS' -Scope 'Template' -ObjectName $templateLabel `
            -Reason 'Direct ESC12 indicator set not observed on this template.' `
            -Recommendation 'Review DC / Kerberos authentication templates with extra care.'
    }

    # ESC13
    if ($isPublished -and $looksLikeDcAuth -and $aclSummary.BroadDangerousWrite) {
        Add-ESCFinding -Esc 'ESC13' -Status 'FAIL' -Scope 'Template ACL' -ObjectName $templateLabel `
            -Reason 'DC-auth-like template has broad dangerous write rights.' `
            -Evidence ($aclSummary.BroadDangerousAceIds -join '; ') `
            -Recommendation 'Restrict dangerous write rights on DC-authentication templates to Tier 0 PKI admins only.'
    }
    else {
        Add-ESCFinding -Esc 'ESC13' -Status 'PASS' -Scope 'Template ACL' -ObjectName $templateLabel `
            -Reason 'No direct ESC13 ACL indicator observed on this template.' `
            -Recommendation 'Review DC-auth template ACLs periodically.'
    }
}

# ---------------------------------------------------------------------
# CA-level and remote posture checks
# ---------------------------------------------------------------------
$dcNames = @()
try {
    $dcNames = @(
        Get-ADDomainController @adSplat -Filter * -ErrorAction Stop |
            Select-Object -ExpandProperty HostName
    )
}
catch {
    Write-Log -Message "Could not enumerate domain controllers for strong mapping checks: $($_.Exception.Message)" -Level 'WARNING'
}

foreach ($ca in $caObjects) {
    $caName   = [string]$ca.Name
    $caHost   = [string]$ca.dNSHostName
    $caDisplay = if ([string]::IsNullOrWhiteSpace($ca.displayName)) {
        $caName
    }
    else {
        "$($ca.displayName) ($caName)"
    }

    $caAclSummary = Get-AclSummary -DistinguishedName $ca.DistinguishedName

    # ESC4
    if ($caAclSummary.BroadDangerousWrite) {
        Add-ESCFinding -Esc 'ESC4' -Status 'FAIL' -Scope 'CA Object ACL' -ObjectName $caDisplay `
            -Reason 'Broad principal has dangerous write rights on the CA enrollment service object.' `
            -Evidence ($caAclSummary.BroadDangerousAceIds -join '; ') `
            -Recommendation 'Restrict dangerous write rights on CA objects to dedicated PKI admins only.'
    }
    else {
        Add-ESCFinding -Esc 'ESC4' -Status 'PASS' -Scope 'CA Object ACL' -ObjectName $caDisplay `
            -Reason 'No broad dangerous write rights observed on the CA object.' `
            -Recommendation 'Continue periodic ACL review.'
    }

    # ESC5
    Add-ESCFinding -Esc 'ESC5' -Status 'REVIEW' -Scope 'CA Security Roles' -ObjectName $caDisplay `
        -Reason 'Certificate Manager / ManageCertificates delegation is not fully inferable from the AD enrollment-service object alone.' `
        -Evidence 'Manual review of CA security roles is recommended.' `
        -Recommendation 'Review CA security roles (ManageCA / ManageCertificates / officer roles) directly on the CA.'

    # ESC7
    Add-ESCFinding -Esc 'ESC7' -Status 'REVIEW' -Scope 'CA Policy' -ObjectName $caDisplay `
        -Reason 'AllowAnyPolicy is not evaluated by this PowerShell-only baseline script.' `
        -Evidence 'Manual CA policy review required.' `
        -Recommendation 'Validate CA policy / policy-module settings directly and ensure they align to enterprise PKI policy.'

    if (-not $SkipRemoteChecks -and -not [string]::IsNullOrWhiteSpace($caHost)) {
        $policyKey = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"

        $editFlags = Get-MSADPTRemoteRegistryValue -ComputerName $caHost -SubKey $policyKey -ValueName 'EditFlags'
        $disableExtList = Get-MSADPTRemoteRegistryValue -ComputerName $caHost -SubKey $policyKey -ValueName 'DisableExtensionList'

        # ESC6
        if ($null -ne $editFlags -and (([int]$editFlags -band $EDITF_ATTRIBUTESUBJECTALTNAME2) -ne 0)) {
            Add-ESCFinding -Esc 'ESC6' -Status 'FAIL' -Scope 'CA EditFlags' -ObjectName $caDisplay `
                -Reason 'CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.' `
                -Evidence "EditFlags=$editFlags" `
                -Recommendation 'Remove EDITF_ATTRIBUTESUBJECTALTNAME2 unless there is a documented and tightly controlled business requirement.'
        }
        elseif ($null -ne $editFlags) {
            Add-ESCFinding -Esc 'ESC6' -Status 'PASS' -Scope 'CA EditFlags' -ObjectName $caDisplay `
                -Reason 'CA does not appear to have EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.' `
                -Evidence "EditFlags=$editFlags" `
                -Recommendation 'Continue periodic review of CA EditFlags.'
        }
        else {
            Add-ESCFinding -Esc 'ESC6' -Status 'REVIEW' -Scope 'CA EditFlags' -ObjectName $caDisplay `
                -Reason 'Could not read CA EditFlags remotely.' `
                -Recommendation 'Review EditFlags directly on the CA.'
        }

        # ESC16 (global SID extension disable)
        $disableExtJoined = if ($disableExtList -is [System.Array]) {
            ($disableExtList -join ';')
        }
        else {
            [string]$disableExtList
        }

        if (-not [string]::IsNullOrWhiteSpace($disableExtJoined) -and $disableExtJoined -like "*$SidSecurityExtensionOid*") {
            Add-ESCFinding -Esc 'ESC16' -Status 'FAIL' -Scope 'CA Policy' -ObjectName $caDisplay `
                -Reason 'CA appears to globally disable the SID security extension.' `
                -Evidence $disableExtJoined `
                -Recommendation 'Remove the SID security extension OID from DisableExtensionList and validate certificate mapping posture.'
        }
        elseif ($null -ne $disableExtList) {
            Add-ESCFinding -Esc 'ESC16' -Status 'PASS' -Scope 'CA Policy' -ObjectName $caDisplay `
                -Reason 'CA does not appear to globally disable the SID security extension.' `
                -Evidence $disableExtJoined `
                -Recommendation 'Continue periodic review of CA policy-module settings.'
        }
        else {
            Add-ESCFinding -Esc 'ESC16' -Status 'REVIEW' -Scope 'CA Policy' -ObjectName $caDisplay `
                -Reason 'Could not read DisableExtensionList remotely.' `
                -Recommendation 'Review the CA policy-module registry settings directly.'
        }

        # ESC8 / ESC15
        $web = Test-MSADPTWebEndpoint -ComputerName $caHost -RelativePath 'certsrv/'

        if ($web.HttpOpen) {
            Add-ESCFinding -Esc 'ESC8' -Status 'FAIL' -Scope 'Web Enrollment' -ObjectName $caDisplay `
                -Reason 'HTTP /certsrv/ endpoint appears reachable.' `
                -Evidence "HttpOpen=$($web.HttpOpen); HttpsOpen=$($web.HttpsOpen)" `
                -Recommendation 'Disable unnecessary web enrollment services or enforce HTTPS + EPA and review NTLM exposure.'

            Add-ESCFinding -Esc 'ESC15' -Status 'REVIEW' -Scope 'Web Enrollment / Relay Surface' -ObjectName $caDisplay `
                -Reason 'HTTP AD CS endpoint exposure increases relay review priority.' `
                -Evidence "HttpOpen=$($web.HttpOpen); HttpsOpen=$($web.HttpsOpen)" `
                -Recommendation 'Review IIS auth providers, Extended Protection for Authentication, and NTLM exposure on AD CS web endpoints.'
        }
        elseif ($web.HttpsOpen) {
            Add-ESCFinding -Esc 'ESC8' -Status 'REVIEW' -Scope 'Web Enrollment' -ObjectName $caDisplay `
                -Reason 'HTTPS /certsrv/ endpoint appears reachable; EPA / NTLM posture still requires manual review.' `
                -Evidence "HttpOpen=$($web.HttpOpen); HttpsOpen=$($web.HttpsOpen)" `
                -Recommendation 'Validate IIS Windows Authentication settings, NTLM usage, and EPA on AD CS web enrollment.'

            Add-ESCFinding -Esc 'ESC15' -Status 'REVIEW' -Scope 'Web Enrollment / Relay Surface' -ObjectName $caDisplay `
                -Reason 'AD CS web enrollment is exposed over HTTPS; relay-hardening controls still require manual verification.' `
                -Evidence "HttpOpen=$($web.HttpOpen); HttpsOpen=$($web.HttpsOpen)" `
                -Recommendation 'Review CES / Web Enrollment NTLM and EPA posture, especially if integrated with ADFS or other certificate auth flows.'
        }
        else {
            Add-ESCFinding -Esc 'ESC8' -Status 'PASS' -Scope 'Web Enrollment' -ObjectName $caDisplay `
                -Reason 'No obvious /certsrv/ endpoint exposure detected by this script.' `
                -Recommendation 'Confirm there are no alternate AD CS HTTP endpoints exposed.'

            Add-ESCFinding -Esc 'ESC15' -Status 'PASS' -Scope 'Web Enrollment / Relay Surface' -ObjectName $caDisplay `
                -Reason 'No obvious AD CS web enrollment endpoint exposure detected by this script.' `
                -Recommendation 'Confirm CES / web endpoints are not enabled elsewhere.'
        }
    }
    else {
        Add-ESCFinding -Esc 'ESC6' -Status 'REVIEW' -Scope 'CA EditFlags' -ObjectName $caDisplay `
            -Reason 'Remote CA checks skipped or CA hostname unavailable.' `
            -Recommendation 'Review CA registry settings directly.'

        Add-ESCFinding -Esc 'ESC8' -Status 'REVIEW' -Scope 'Web Enrollment' -ObjectName $caDisplay `
            -Reason 'Remote web enrollment checks skipped or CA hostname unavailable.' `
            -Recommendation 'Review AD CS HTTP(S) endpoints manually.'

        Add-ESCFinding -Esc 'ESC15' -Status 'REVIEW' -Scope 'Web Enrollment / Relay Surface' -ObjectName $caDisplay `
            -Reason 'Remote relay-surface checks skipped or CA hostname unavailable.' `
            -Recommendation 'Review AD CS web enrollment / CES exposure manually.'

        Add-ESCFinding -Esc 'ESC16' -Status 'REVIEW' -Scope 'CA Policy' -ObjectName $caDisplay `
            -Reason 'Remote CA policy checks skipped or CA hostname unavailable.' `
            -Recommendation 'Review DisableExtensionList directly on the CA.'
    }
}

# ---------------------------------------------------------------------
# Domain controller / mapping posture checks
# ---------------------------------------------------------------------
if (-not $SkipRemoteChecks -and $dcNames.Count -gt 0) {
    foreach ($dc in $dcNames) {
        $kdcValue = Get-MSADPTRemoteRegistryValue -ComputerName $dc -SubKey 'SYSTEM\CurrentControlSet\Services\Kdc' -ValueName 'StrongCertificateBindingEnforcement'

        if ($null -eq $kdcValue) {
            Add-ESCFinding -Esc 'ESC10' -Status 'REVIEW' -Scope 'DC Mapping Posture' -ObjectName $dc `
                -Reason 'Could not read StrongCertificateBindingEnforcement remotely.' `
                -Recommendation 'Review DC certificate mapping posture directly and verify strong mapping enforcement.'

            Add-ESCFinding -Esc 'ESC11' -Status 'REVIEW' -Scope 'DC Mapping / PKINIT Posture' -ObjectName $dc `
                -Reason 'Relay / PKINIT posture cannot be inferred without complete DC mapping and service review.' `
                -Recommendation 'Review PKINIT, certificate mapping enforcement, and relay hardening on DCs manually.'

            continue
        }

        switch ([int]$kdcValue) {
            2 {
                Add-ESCFinding -Esc 'ESC10' -Status 'PASS' -Scope 'DC Mapping Posture' -ObjectName $dc `
                    -Reason 'DC is configured for strong certificate binding enforcement.' `
                    -Evidence "StrongCertificateBindingEnforcement=2" `
                    -Recommendation 'Keep DCs in full enforcement mode.'
            }
            1 {
                Add-ESCFinding -Esc 'ESC10' -Status 'FAIL' -Scope 'DC Mapping Posture' -ObjectName $dc `
                    -Reason 'DC is in compatibility mode for certificate binding.' `
                    -Evidence "StrongCertificateBindingEnforcement=1" `
                    -Recommendation 'Move DCs to full enforcement mode after reissuing non-compliant certificates as needed.'
            }
            default {
                Add-ESCFinding -Esc 'ESC10' -Status 'REVIEW' -Scope 'DC Mapping Posture' -ObjectName $dc `
                    -Reason 'Unexpected StrongCertificateBindingEnforcement value observed.' `
                    -Evidence "StrongCertificateBindingEnforcement=$kdcValue" `
                    -Recommendation 'Review DC certificate binding posture directly.'
            }
        }

        Add-ESCFinding -Esc 'ESC11' -Status 'REVIEW' -Scope 'DC Mapping / PKINIT Posture' -ObjectName $dc `
            -Reason 'ESC11-style relay / PKINIT conditions depend on more than this registry value alone.' `
            -Evidence "StrongCertificateBindingEnforcement=$kdcValue" `
            -Recommendation 'Review PKINIT-enabled auth paths, relay protections, NTLM restrictions, and certificate trust chains manually.'
    }
}
else {
    Add-ESCFinding -Esc 'ESC10' -Status 'REVIEW' -Scope 'DC Mapping Posture' -ObjectName 'Domain Controllers' `
        -Reason 'Remote DC checks skipped or no DCs were enumerated.' `
        -Recommendation 'Review StrongCertificateBindingEnforcement directly on DCs.'

    Add-ESCFinding -Esc 'ESC11' -Status 'REVIEW' -Scope 'DC Mapping / PKINIT Posture' -ObjectName 'Domain Controllers' `
        -Reason 'Remote DC checks skipped or no DCs were enumerated.' `
        -Recommendation 'Review PKINIT / relay posture on DCs manually.'
}

# ---------------------------------------------------------------------
# ESC16-DNSADMIN (environmental chain review)
# ---------------------------------------------------------------------
try {
    $dnsAdmins = Get-ADGroup @adSplat -Identity 'DnsAdmins' -ErrorAction Stop
    $dnsAdminMembers = @(
        Get-ADGroupMember @adSplat -Identity $dnsAdmins -Recursive -ErrorAction Stop
    )

    $suspiciousDnsAdminMembers = @(
        $dnsAdminMembers |
            Where-Object {
                $_.objectClass -eq 'user' -or $_.objectClass -eq 'group'
            } |
            Select-Object -ExpandProperty SamAccountName
    )

    if ($suspiciousDnsAdminMembers.Count -gt 0) {
        Add-ESCFinding -Esc 'ESC16-DNSADMIN' -Status 'REVIEW' -Scope 'DnsAdmins' -ObjectName 'DnsAdmins' `
            -Reason 'DnsAdmins membership exists and should be reviewed in any environment where DNS and CA trust relationships intersect.' `
            -Evidence ($suspiciousDnsAdminMembers -join '; ') `
            -Recommendation 'Review whether CA infrastructure depends on DNS-admin-controlled paths and restrict DnsAdmins membership accordingly.'
    }
    else {
        Add-ESCFinding -Esc 'ESC16-DNSADMIN' -Status 'PASS' -Scope 'DnsAdmins' -ObjectName 'DnsAdmins' `
            -Reason 'No DnsAdmins members were returned by the current query.' `
            -Recommendation 'Continue reviewing privileged DNS administration paths.'
    }
}
catch {
    Add-ESCFinding -Esc 'ESC16-DNSADMIN' -Status 'REVIEW' -Scope 'DnsAdmins' -ObjectName 'DnsAdmins' `
        -Reason 'Could not enumerate DnsAdmins membership.' `
        -Recommendation 'Review DnsAdmins membership and DNS-to-CA dependency paths manually.'
}

# ---------------------------------------------------------------------
# Persist findings
# ---------------------------------------------------------------------
$OutputCsvPath = Join-Path $OutputBaseDir "MSADPT_ADCS_ESC_Audit_$ScriptStartTime.csv"
$Findings | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Force

Write-Log -Message "AD CS ESC audit completed." -Level 'INFO'
Write-Log -Message "Findings written to '$OutputCsvPath'." -Level 'INFO'

# ---------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------
$summary = $Findings | Group-Object ESC, Status | Sort-Object Name

Write-Log -Message "Summary:" -Level 'INFO'
foreach ($item in $summary) {
    Write-Log -Message "  $($item.Name) = $($item.Count)" -Level 'INFO'
}
