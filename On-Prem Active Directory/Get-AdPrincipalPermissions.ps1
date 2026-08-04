#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#+
.SYNOPSIS
    Audits Active Directory access control entries that apply to a user or any
    Active Directory security group in the user's group membership chain.

.DESCRIPTION
    Enumerates objects beneath a specified LDAP search base, reads each object's
    security descriptor, and returns every allow ACE whose identity matches the
    target user or one of the user's direct or nested Active Directory security
    groups.

    Matching is SID-based to avoid ambiguity caused by renamed accounts,
    duplicate display names, or differing domain-qualified account formats.

    This script is read-only. It does not change Active Directory permissions.

.PARAMETER Username
    User identity accepted by Get-ADUser, such as:
      CONTOSO\jdoe
      jdoe@contoso.com
      jdoe
      CN=Jane Doe,OU=Users,DC=contoso,DC=com

.PARAMETER Domain
    Distinguished name of the LDAP search base. The parameter name is retained
    for compatibility with the original script. The domain DNS name is also
    accepted and is converted to the domain distinguished name.

    Examples:
      contoso.com
      DC=contoso,DC=com
      OU=Privileged Accounts,DC=contoso,DC=com

.PARAMETER Server
    Optional domain controller or AD LDS instance to query.

.PARAMETER OutputPath
    Optional CSV output path. The complete result set is still emitted to the
    PowerShell pipeline.

.PARAMETER IncludeDeny
    Includes matching deny ACEs. By default, only permission grants are returned.

.PARAMETER IncludeNonSecurityGroups
    Includes distribution groups in the principal inventory. Distribution group
    SIDs do not normally appear in authorization tokens, so they are excluded by
    default.

.EXAMPLE
    .\ad_object_permissions3.ps1 `
        -Username 'CONTOSO\jdoe' `
        -Domain 'DC=contoso,DC=com'

.EXAMPLE
    .\ad_object_permissions3.ps1 `
        -Username 'jdoe@contoso.com' `
        -Domain 'OU=Servers,DC=contoso,DC=com' `
        -OutputPath '.\jdoe-ad-permissions.csv'

.OUTPUTS
    PSCustomObject with one row per matching ACE.

.NOTES
    Version 2.0.0
    Generic public-repository version. No organization-specific identifiers are
    embedded in the script.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory, Position = 1)]
    [Alias('SearchBase')]
    [ValidatePattern('^(?i)(CN|OU|DC)=.+')]
    [string]$Domain,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludeDeny,

    [Parameter()]
    [switch]$IncludeNonSecurityGroups
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-IdentityLeaf {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity
    )

    if ($Identity -match '^[^\\]+\\(.+)$') {
        return $Matches[1]
    }

    return $Identity
}

function Resolve-AdSearchBase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InputValue,

        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADDomain]$AdDomain
    )

    $value = $InputValue.Trim()
    $domainDn = $AdDomain.DistinguishedName
    $dnsRoot = $AdDomain.DNSRoot

    # Accept a DNS domain name as a convenience, for example contoso.com.
    if ($value -notmatch '^(?i)(CN|OU|DC)=') {
        if ($value -ieq $dnsRoot) {
            return $domainDn
        }

        throw "Search base '$InputValue' is neither a distinguished name nor the DNS name '$dnsRoot'. Expected a value such as '$domainDn' or 'OU=Servers,$domainDn'."
    }

    # Preserve compatibility with a common malformed form such as
    # DC=contoso.com,DC=com. A DNS label must not be embedded inside one DC= RDN.
    if ($value -match '^(?i)DC=([^,]+\.[^,]+)(,DC=[^,]+)+$') {
        $candidateDnsName = (($value -split ',') | ForEach-Object {
            $_ -replace '^(?i)DC=', ''
        }) -join '.'

        $firstLabelWithSuffix = (($value -split ',')[0] -replace '^(?i)DC=', '')
        $remainingLabels = @(($value -split ',')[1..(($value -split ',').Count - 1)] | ForEach-Object {
            $_ -replace '^(?i)DC=', ''
        })

        if ($remainingLabels.Count -gt 0) {
            $suffix = $remainingLabels -join '.'
            if ($firstLabelWithSuffix.EndsWith(".$suffix", [System.StringComparison]::OrdinalIgnoreCase)) {
                $firstLabel = $firstLabelWithSuffix.Substring(0, $firstLabelWithSuffix.Length - $suffix.Length - 1)
                $corrected = (@("DC=$firstLabel") + ($remainingLabels | ForEach-Object { "DC=$_" })) -join ','

                if ($corrected -ieq $domainDn) {
                    Write-Warning "Corrected malformed search base '$InputValue' to '$corrected'. In a distinguished name, each DNS label must be a separate DC= component."
                    return $corrected
                }
            }
        }

        Write-Verbose "Malformed domain-DN candidate resolved to '$candidateDnsName', but it did not match '$dnsRoot'."
    }

    if ($value -ieq $domainDn -or $value.EndsWith(",$domainDn", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $value
    }

    throw "Search base '$InputValue' does not belong to the queried domain partition '$domainDn'. Use '$domainDn' for the entire domain or an OU/container beneath it."
}

function Get-RiskAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectoryRights]$Rights,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AccessControlType]$AccessControlType
    )

    if ($AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
        return [pscustomobject]@{
            Severity = 'Informational'
            Reason   = 'Matching deny ACE; this entry restricts access rather than granting it.'
        }
    }

    $criticalFlags = @(
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    )

    foreach ($flag in $criticalFlags) {
        if (($Rights -band $flag) -eq $flag) {
            return [pscustomobject]@{
                Severity = 'Critical'
                Reason   = 'GenericAll grants unrestricted control over the affected object scope.'
            }
        }
    }

    $highFlags = @(
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
        [System.DirectoryServices.ActiveDirectoryRights]::Delete,
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree,
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild,
        [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
    )

    $highMatches = foreach ($flag in $highFlags) {
        if (($Rights -band $flag) -eq $flag) {
            $flag.ToString()
        }
    }

    if ($highMatches) {
        return [pscustomobject]@{
            Severity = 'High'
            Reason   = 'Sensitive control or modification rights: {0}.' -f ($highMatches -join ', ')
        }
    }

    $mediumFlags = @(
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::Self
    )

    $mediumMatches = foreach ($flag in $mediumFlags) {
        if (($Rights -band $flag) -eq $flag) {
            $flag.ToString()
        }
    }

    if ($mediumMatches) {
        return [pscustomobject]@{
            Severity = 'Medium'
            Reason   = 'Attribute or validated-write capability: {0}. Impact depends on the scoped attribute or object type.' -f ($mediumMatches -join ', ')
        }
    }

    return [pscustomobject]@{
        Severity = 'Low'
        Reason   = 'Read, list, or otherwise limited rights; review in the context of the target object.'
    }
}

function Resolve-SchemaGuidMap {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server
    )

    $map = @{
        ([guid]::Empty.Guid) = 'All'
    }

    try {
        $rootDseParams = @{}
        if ($Server) {
            $rootDseParams.Server = $Server
        }

        $rootDse = Get-ADRootDSE @rootDseParams

        $schemaParams = @{
            SearchBase = $rootDse.SchemaNamingContext
            LDAPFilter = '(|(schemaIDGUID=*)(rightsGuid=*))'
            Properties = @('lDAPDisplayName', 'name', 'schemaIDGUID', 'rightsGuid')
        }
        if ($Server) {
            $schemaParams.Server = $Server
        }

        foreach ($entry in Get-ADObject @schemaParams) {
            $displayName = if ($entry.lDAPDisplayName) {
                [string]$entry.lDAPDisplayName
            }
            else {
                [string]$entry.Name
            }

            if ($entry.schemaIDGUID) {
                try {
                    $guid = [guid]::new([byte[]]$entry.schemaIDGUID)
                    $map[$guid.Guid] = $displayName
                }
                catch {
                    Write-Verbose "Could not resolve schema GUID for '$($entry.DistinguishedName)': $($_.Exception.Message)"
                }
            }

            if ($entry.rightsGuid) {
                try {
                    $guid = [guid]$entry.rightsGuid
                    $map[$guid.Guid] = $displayName
                }
                catch {
                    Write-Verbose "Could not resolve extended-right GUID for '$($entry.DistinguishedName)': $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-Warning "Schema GUID names could not be loaded. GUID values will still be reported. $($_.Exception.Message)"
    }

    return $map
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $adCommon = @{}
    if ($Server) {
        $adCommon.Server = $Server
    }

    $identityForLookup = Get-IdentityLeaf -Identity $Username
    $user = Get-ADUser -Identity $identityForLookup -Properties SID, SamAccountName, UserPrincipalName @adCommon

    $principalBySid = @{}
    $principalBySid[$user.SID.Value] = [pscustomobject]@{
        PrincipalName = $user.SamAccountName
        PrincipalType = 'User'
        DistinguishedName = $user.DistinguishedName
    }

    $groupParams = @{
        Identity = $user
    }
    foreach ($key in $adCommon.Keys) {
        $groupParams[$key] = $adCommon[$key]
    }

    foreach ($group in Get-ADPrincipalGroupMembership @groupParams) {
        if (-not $IncludeNonSecurityGroups -and $group.GroupCategory -ne 'Security') {
            continue
        }

        if (-not $group.SID) {
            continue
        }

        $principalBySid[$group.SID.Value] = [pscustomobject]@{
            PrincipalName = $group.SamAccountName
            PrincipalType = '{0} Group' -f $group.GroupCategory
            DistinguishedName = $group.DistinguishedName
        }
    }

    $domainParams = @{}
    if ($Server) {
        $domainParams.Server = $Server
    }

    $adDomain = Get-ADDomain @domainParams
    $searchBase = Resolve-AdSearchBase -InputValue $Domain -AdDomain $adDomain
    $schemaGuidMap = Resolve-SchemaGuidMap -Server $Server

    Write-Verbose "Searching beneath '$searchBase'."
    Write-Verbose "Matching $($principalBySid.Count) SID-based principals for '$($user.SamAccountName)'."

    $queryParams = @{
        LDAPFilter    = '(objectClass=*)'
        SearchBase    = $searchBase
        SearchScope   = 'Subtree'
        Properties    = @('nTSecurityDescriptor', 'objectClass')
        ResultSetSize = $null
    }
    foreach ($key in $adCommon.Keys) {
        $queryParams[$key] = $adCommon[$key]
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $objectCount = 0

    foreach ($adObject in Get-ADObject @queryParams) {
        $objectCount++

        $acl = $adObject.nTSecurityDescriptor
        if (-not $acl) {
            Write-Verbose "No readable security descriptor for '$($adObject.DistinguishedName)'."
            continue
        }

        foreach ($ace in $acl.Access) {
            if (-not $IncludeDeny -and $ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                continue
            }

            $aceSid = $null
            try {
                $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                Write-Verbose "Could not translate ACE identity '$($ace.IdentityReference)' on '$($adObject.DistinguishedName)' to a SID."
                continue
            }

            if (-not $principalBySid.ContainsKey($aceSid)) {
                continue
            }

            $principal = $principalBySid[$aceSid]
            $risk = Get-RiskAssessment -Rights $ace.ActiveDirectoryRights -AccessControlType $ace.AccessControlType

            $objectTypeGuid = $ace.ObjectType.Guid
            $inheritedObjectTypeGuid = $ace.InheritedObjectType.Guid

            $objectTypeName = if ($schemaGuidMap.ContainsKey($objectTypeGuid)) {
                $schemaGuidMap[$objectTypeGuid]
            }
            else {
                $objectTypeGuid
            }

            $inheritedObjectTypeName = if ($schemaGuidMap.ContainsKey($inheritedObjectTypeGuid)) {
                $schemaGuidMap[$inheritedObjectTypeGuid]
            }
            else {
                $inheritedObjectTypeGuid
            }

            $results.Add([pscustomobject][ordered]@{
                ObjectDN               = $adObject.DistinguishedName
                ObjectClass            = ($adObject.ObjectClass -join ',')
                Principal              = $principal.PrincipalName
                PrincipalType          = $principal.PrincipalType
                PrincipalSID           = $aceSid
                AccessControlType       = $ace.AccessControlType.ToString()
                Rights                  = $ace.ActiveDirectoryRights.ToString()
                RiskSeverity            = $risk.Severity
                RiskReason              = $risk.Reason
                IsInherited             = [bool]$ace.IsInherited
                InheritanceType         = $ace.InheritanceType.ToString()
                ObjectType              = $objectTypeName
                ObjectTypeGuid          = $objectTypeGuid
                InheritedObjectType     = $inheritedObjectTypeName
                InheritedObjectTypeGuid = $inheritedObjectTypeGuid
            })
        }
    }

    $severityOrder = @{
        Critical      = 0
        High          = 1
        Medium        = 2
        Low           = 3
        Informational = 4
    }

    $sortedResults = @(
        $results |
            Sort-Object `
                @{ Expression = { $severityOrder[$_.RiskSeverity] } },
                ObjectDN,
                Principal,
                Rights
    )

    if ($OutputPath) {
        $resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        $parentPath = Split-Path -Path $resolvedOutputPath -Parent

        if ($parentPath -and -not (Test-Path -LiteralPath $parentPath -PathType Container)) {
            $null = New-Item -Path $parentPath -ItemType Directory -Force
        }

        $sortedResults | Export-Csv -LiteralPath $resolvedOutputPath -NoTypeInformation -Encoding UTF8
        Write-Verbose "Exported $($sortedResults.Count) matching ACEs to '$resolvedOutputPath'."
    }

    Write-Verbose "Scanned $objectCount AD objects and found $($sortedResults.Count) matching ACEs."
    Write-Output $sortedResults
}
catch {
    $message = "Active Directory permission audit failed: $($_.Exception.Message)"
    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
        $_.Exception,
        'AdPermissionAuditFailed',
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        $Username
    )
    $errorRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($message)
    $PSCmdlet.ThrowTerminatingError($errorRecord)
}
