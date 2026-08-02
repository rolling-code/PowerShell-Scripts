#requires -Version 5.1
<#
.SYNOPSIS
Audits tenant default user permissions, active Microsoft Entra directory-role assignments, and high-privilege Azure RBAC assignments.

.DESCRIPTION
Produces a tenant-wide, read-only report of users whose effective privileges exceed the tenant's
configured default user role permissions. The script:

- Reuses the current Microsoft Graph session. It never requests new consent or disconnects it.
- Retrieves defaultUserRolePermissions from the Microsoft Entra authorization policy.
- Enumerates active Microsoft Entra directory-role assignments using Microsoft Graph v1.0.
- Treats every active directory-role assignment as elevated beyond the default user role.
- Expands role-assignable group assignments to transitive user members.
- Audits Owner, Contributor, and User Access Administrator Azure RBAC assignments across accessible
  enabled subscriptions, unless -SkipAzureRbac is used.
- Expands Azure RBAC group assignments to transitive user members when Graph can resolve the group.
- Reports only users with at least one active Entra directory role or high-privilege Azure RBAC assignment.
- Creates timestamped CSV and JSON evidence, coverage, defaults, and warning reports.

The script audits active assignments through Microsoft Graph v1.0. Every active Microsoft Entra
directory-role assignment is treated as elevated beyond the default user role. The script does not
enumerate eligible Microsoft Entra PIM assignments or eligible Azure RBAC schedules.

.PARAMETER OutputPath
Directory for timestamped reports. Defaults to the script directory.

.PARAMETER HighPrivilegeAzureRoles
Azure RBAC role names considered high privilege. Defaults to Owner, Contributor, and User Access Administrator.

.PARAMETER SubscriptionId
Optional Azure subscription IDs to audit. If omitted, all enabled subscriptions visible to the
current Az session are evaluated.

.PARAMETER SkipAzureRbac
Skips Azure RBAC collection. Useful when only Microsoft Entra role assignments and tenant defaults
need to be assessed.

.PARAMETER IncludeDisabledUsers
Includes disabled users in the elevated-user findings. By default, disabled users are excluded from
the primary findings but remain visible in the coverage report.

.EXAMPLE
.\Audit-AllUsersRolePerms.ps1

.EXAMPLE
.\Audit-AllUsersRolePerms.ps1 -OutputPath .\Reports

.EXAMPLE
.\Audit-AllUsersRolePerms.ps1 -SubscriptionId @(
    '11111111-1111-1111-1111-111111111111',
    '22222222-2222-2222-2222-222222222222'
)

.EXAMPLE
.\Audit-AllUsersRolePerms.ps1 -SkipAzureRbac

.NOTES
Required existing Microsoft Graph delegated visibility:
- Policy.Read.All for authorizationPolicy/defaultUserRolePermissions.
- RoleManagement.Read.Directory for Microsoft Entra role definitions and assignments.
- User.Read.All or Directory.Read.All for complete user details.
- GroupMember.Read.All or Directory.Read.All to expand group-based assignments.

Azure RBAC collection additionally requires an active Az PowerShell context and sufficient Azure
RBAC visibility in each audited subscription. The script does not install modules or authenticate
interactively.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$HighPrivilegeAzureRoles = @(
        'Owner',
        'Contributor',
        'User Access Administrator'
    ),

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string[]]$SubscriptionId,

    [Parameter()]
    [switch]$SkipAzureRbac,

    [Parameter()]
    [switch]$IncludeDisabledUsers
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-OptionalProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$DefaultValue = ''
    )

    if ($null -eq $InputObject) { return $DefaultValue }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $DefaultValue }
    return $property.Value
}

function ConvertTo-NormalizedId {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return ([string]$Value).Trim().Trim('{}').ToLowerInvariant()
}

function ConvertTo-UtcText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return '' }
    try { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    catch { return [string]$Value }
}

function Get-GraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $requestParameters = @{
            Method     = 'GET'
            Uri        = $nextUri
            OutputType = 'PSObject'
        }
        if ($null -ne $Headers -and $Headers.Count -gt 0) {
            $requestParameters.Headers = $Headers
        }

        $response = Invoke-MgGraphRequest @requestParameters
        $valueProperty = $response.PSObject.Properties['value']

        if ($null -ne $valueProperty) {
            foreach ($item in @($valueProperty.Value)) {
                if ($null -ne $item) { $items.Add($item) }
            }
        } elseif ($null -ne $response) {
            $items.Add($response)
        }

        $nextUri = [string](Get-OptionalProperty -InputObject $response -Name '@odata.nextLink')
    }

    return $items.ToArray()
}

function Invoke-OptionalGraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$DataSet,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Warnings,
        [hashtable]$Headers
    )

    try {
        return @(Get-GraphCollection -Uri $Uri -Headers $Headers)
    } catch {
        $message = "$DataSet could not be retrieved: $($_.Exception.Message)"
        $Warnings.Add([pscustomobject]@{ DataSet=$DataSet; Message=$message })
        Write-Warning $message
        return @()
    }
}

function Export-CsvWithHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string[]]$Headers,
        [Parameter(Mandatory)][string]$LiteralPath
    )

    if (@($Rows).Count -gt 0) {
        $Rows | Select-Object -Property $Headers |
            Export-Csv -LiteralPath $LiteralPath -NoTypeInformation -Encoding UTF8
        return
    }

    $template = [ordered]@{}
    foreach ($header in $Headers) { $template[$header] = '' }
    $headerLine = ([pscustomobject]$template | ConvertTo-Csv -NoTypeInformation)[0]
    Set-Content -LiteralPath $LiteralPath -Value $headerLine -Encoding UTF8
}

function Get-GraphGroupTransitiveUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][hashtable]$Cache,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Warnings,
        [hashtable]$Headers
    )

    $normalizedGroupId = ConvertTo-NormalizedId $GroupId
    if ($Cache.ContainsKey($normalizedGroupId)) {
        return @($Cache[$normalizedGroupId])
    }

    $uri = "https://graph.microsoft.com/v1.0/groups/${normalizedGroupId}/transitiveMembers/microsoft.graph.user?`$select=id,displayName,userPrincipalName,accountEnabled,userType&`$top=999"
    $users = @(Invoke-OptionalGraphCollection -Uri $uri -DataSet "Transitive members of group $normalizedGroupId" -Warnings $Warnings -Headers $Headers)
    $Cache[$normalizedGroupId] = @($users)
    return @($users)
}

function Add-UserPrivilegeEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$EvidenceByUser,
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][object]$Evidence
    )

    $normalizedUserId = ConvertTo-NormalizedId $UserId
    if ([string]::IsNullOrWhiteSpace($normalizedUserId)) { return }

    if (-not $EvidenceByUser.ContainsKey($normalizedUserId)) {
        $EvidenceByUser[$normalizedUserId] = [System.Collections.Generic.List[object]]::new()
    }
    $EvidenceByUser[$normalizedUserId].Add($Evidence)
}

$requiredGraphCommands = @('Get-MgContext','Invoke-MgGraphRequest')
$missingGraphCommands = @(
    $requiredGraphCommands | Where-Object {
        -not (Get-Command $_ -ErrorAction SilentlyContinue)
    }
)
if ($missingGraphCommands.Count -gt 0) {
    throw "Missing Microsoft Graph command(s): $($missingGraphCommands -join ', '). Install or update Microsoft.Graph.Authentication."
}

$graphContext = Get-MgContext
if ($null -eq $graphContext) {
    throw 'No active Microsoft Graph session was found. Connect using permissions already approved for your environment, then rerun the script.'
}

$normalizedScopes = @($graphContext.Scopes | ForEach-Object { [string]$_ })
$recommendedScopes = @(
    'Policy.Read.All',
    'RoleManagement.Read.Directory',
    'User.Read.All',
    'GroupMember.Read.All'
)
$missingRecommendedScopes = @(
    $recommendedScopes | Where-Object {
        $normalizedScopes -notcontains $_ -and $normalizedScopes -notcontains 'Directory.Read.All'
    }
)
if ($missingRecommendedScopes.Count -gt 0) {
    Write-Warning "The current Graph session does not advertise recommended scope(s): $($missingRecommendedScopes -join ', '). Existing broader permissions or directory roles may still provide access; no new consent will be requested."
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
}
$resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$prefix = Join-Path $resolvedOutputPath "all-users-role-permissions-audit-$timestamp"
$warnings = [System.Collections.Generic.List[object]]::new()
$groupUserCache = @{}
$userById = @{}
$evidenceByUser = @{}
$advancedHeaders = @{ ConsistencyLevel = 'eventual' }

Write-Host "Reusing Microsoft Graph session for $($graphContext.Account). No new consent request will be made." -ForegroundColor Cyan
Write-Host "Tenant ID: $($graphContext.TenantId) | Authentication: $($graphContext.AuthType)" -ForegroundColor DarkGray

Write-Host 'Retrieving tenant default user role permissions...' -ForegroundColor Cyan
$authorizationPolicyUri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy?$select=id,displayName,guestUserRoleId,defaultUserRolePermissions'
$authorizationPolicy = Invoke-MgGraphRequest -Method GET -Uri $authorizationPolicyUri -OutputType PSObject
$defaultPermissions = Get-OptionalProperty -InputObject $authorizationPolicy -Name 'defaultUserRolePermissions' -DefaultValue $null
if ($null -eq $defaultPermissions) {
    throw 'Microsoft Graph returned no defaultUserRolePermissions in the authorization policy.'
}

$permissionGrantPolicies = @(
    Get-OptionalProperty -InputObject $defaultPermissions -Name 'permissionGrantPoliciesAssigned' -DefaultValue @()
)
$defaultRows = @(
    [pscustomobject][ordered]@{ Setting='allowedToCreateApps'; Value=Get-OptionalProperty $defaultPermissions 'allowedToCreateApps'; Interpretation=$(if([bool](Get-OptionalProperty $defaultPermissions 'allowedToCreateApps')){'Default users can register applications.'}else{'Default users cannot register applications.'}) }
    [pscustomobject][ordered]@{ Setting='allowedToCreateSecurityGroups'; Value=Get-OptionalProperty $defaultPermissions 'allowedToCreateSecurityGroups'; Interpretation=$(if([bool](Get-OptionalProperty $defaultPermissions 'allowedToCreateSecurityGroups')){'Default users can create security groups.'}else{'Default users cannot create security groups.'}) }
    [pscustomobject][ordered]@{ Setting='allowedToCreateTenants'; Value=Get-OptionalProperty $defaultPermissions 'allowedToCreateTenants'; Interpretation=$(if([bool](Get-OptionalProperty $defaultPermissions 'allowedToCreateTenants')){'Default users can create Microsoft Entra tenants.'}else{'Default users cannot create Microsoft Entra tenants.'}) }
    [pscustomobject][ordered]@{ Setting='allowedToReadBitlockerKeysForOwnedDevice'; Value=Get-OptionalProperty $defaultPermissions 'allowedToReadBitlockerKeysForOwnedDevice'; Interpretation=$(if([bool](Get-OptionalProperty $defaultPermissions 'allowedToReadBitlockerKeysForOwnedDevice')){'Owners can read BitLocker recovery keys for their owned devices.'}else{'Owners cannot read BitLocker recovery keys for their owned devices through the default user role.'}) }
    [pscustomobject][ordered]@{ Setting='allowedToReadOtherUsers'; Value=Get-OptionalProperty $defaultPermissions 'allowedToReadOtherUsers'; Interpretation=$(if([bool](Get-OptionalProperty $defaultPermissions 'allowedToReadOtherUsers')){'Default users can read other users.'}else{'Default users cannot read other users.'}) }
    [pscustomobject][ordered]@{ Setting='permissionGrantPoliciesAssigned'; Value=($permissionGrantPolicies -join ';'); Interpretation=$(if($permissionGrantPolicies.Count -gt 0){'User consent is governed by the listed permission grant policy assignments.'}else{'User self-consent is disabled by the default role policy.'}) }
)

Write-Host 'Retrieving tenant users...' -ForegroundColor Cyan
$allUsers = @(Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime&$top=999')
foreach ($user in $allUsers) {
    $userId = ConvertTo-NormalizedId (Get-OptionalProperty $user 'id')
    if ($userId) { $userById[$userId] = $user }
}

Write-Host 'Retrieving Microsoft Entra role definitions and active assignments...' -ForegroundColor Cyan
Write-Host 'Role definitions and assignments source: Microsoft Graph v1.0.' -ForegroundColor DarkGray
Write-Host 'Role-definition and role-assignment requests use bare collection endpoints for tenant compatibility.' -ForegroundColor DarkGray
$roleDefinitions = @(Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions')
$roleDefinitionById = @{}
foreach ($definition in $roleDefinitions) {
    $definitionId = ConvertTo-NormalizedId (Get-OptionalProperty $definition 'id')
    if ($definitionId) { $roleDefinitionById[$definitionId] = $definition }
}

$roleAssignments = @(Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments')
$principalIds = @(
    $roleAssignments |
        ForEach-Object { ConvertTo-NormalizedId (Get-OptionalProperty $_ 'principalId') } |
        Where-Object { $_ } |
        Sort-Object -Unique
)
$principalById = @{}
if ($principalIds.Count -gt 0) {
    foreach ($chunkStart in 0..([math]::Floor(($principalIds.Count - 1) / 1000))) {
        $start = $chunkStart * 1000
        $end = [math]::Min($start + 999, $principalIds.Count - 1)
        $chunk = @($principalIds[$start..$end])
        $body = @{ ids=$chunk; types=@('user','group','servicePrincipal') } | ConvertTo-Json -Depth 4
        try {
            $response = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds?$select=id,displayName,userPrincipalName,accountEnabled,userType' -Body $body -ContentType 'application/json' -OutputType PSObject
            foreach ($principal in @((Get-OptionalProperty $response 'value' @()))) {
                $principalId = ConvertTo-NormalizedId (Get-OptionalProperty $principal 'id')
                if ($principalId) { $principalById[$principalId] = $principal }
            }
        } catch {
            $warnings.Add([pscustomobject]@{ DataSet='Directory role principals'; Message="Batch principal resolution failed: $($_.Exception.Message)" })
        }
    }
}

$entraEvidenceRows = @()
foreach ($assignment in $roleAssignments) {
    $definitionId = ConvertTo-NormalizedId (Get-OptionalProperty $assignment 'roleDefinitionId')
    if (-not $roleDefinitionById.ContainsKey($definitionId)) { continue }

    $definition = $roleDefinitionById[$definitionId]
    $isEnabled = [bool](Get-OptionalProperty $definition 'isEnabled' $true)
    if (-not $isEnabled) { continue }

    $principalId = ConvertTo-NormalizedId (Get-OptionalProperty $assignment 'principalId')
    $principal = if ($principalById.ContainsKey($principalId)) { $principalById[$principalId] } else { $null }
    $odataType = [string](Get-OptionalProperty $principal '@odata.type')
    $roleName = [string](Get-OptionalProperty $definition 'displayName')
    $directoryScope = [string](Get-OptionalProperty $assignment 'directoryScopeId' '/')
    $assignmentId = [string](Get-OptionalProperty $assignment 'id')

    if ($odataType -eq '#microsoft.graph.user' -or $userById.ContainsKey($principalId)) {
        $evidence = [pscustomobject][ordered]@{
            Source='MicrosoftEntra'; AssignmentPath='Direct'; UserId=$principalId; RoleName=$roleName
            RoleDefinitionId=$definitionId; Scope=$directoryScope; AssignmentId=$assignmentId
            SourcePrincipalId=$principalId; SourcePrincipalName=Get-OptionalProperty $principal 'displayName'
            SubscriptionId=''; SubscriptionName=''
        }
        $entraEvidenceRows += $evidence
        Add-UserPrivilegeEvidence -EvidenceByUser $evidenceByUser -UserId $principalId -Evidence $evidence
        continue
    }

    if ($odataType -eq '#microsoft.graph.group') {
        $groupName = [string](Get-OptionalProperty $principal 'displayName' $principalId)
        $groupUsers = @(Get-GraphGroupTransitiveUsers -GroupId $principalId -Cache $groupUserCache -Warnings $warnings -Headers $advancedHeaders)
        foreach ($groupUser in $groupUsers) {
            $groupUserId = ConvertTo-NormalizedId (Get-OptionalProperty $groupUser 'id')
            if ($groupUserId -and -not $userById.ContainsKey($groupUserId)) { $userById[$groupUserId] = $groupUser }
            $evidence = [pscustomobject][ordered]@{
                Source='MicrosoftEntra'; AssignmentPath='ViaGroup'; UserId=$groupUserId; RoleName=$roleName
                RoleDefinitionId=$definitionId; Scope=$directoryScope; AssignmentId=$assignmentId
                SourcePrincipalId=$principalId; SourcePrincipalName=$groupName
                SubscriptionId=''; SubscriptionName=''
            }
            $entraEvidenceRows += $evidence
            Add-UserPrivilegeEvidence -EvidenceByUser $evidenceByUser -UserId $groupUserId -Evidence $evidence
        }
    }
}

$azureEvidenceRows = @()
$auditedSubscriptions = @()
$successfulAzureSubscriptionAudits = [System.Collections.Generic.List[string]]::new()
if (-not $SkipAzureRbac) {
    $requiredAzCommands = @('Get-AzContext','Get-AzSubscription','Set-AzContext','Get-AzRoleAssignment')
    $missingAzCommands = @($requiredAzCommands | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
    if ($missingAzCommands.Count -gt 0) {
        throw "Azure RBAC auditing was requested, but required Az command(s) are missing: $($missingAzCommands -join ', '). Install Az.Accounts and Az.Resources, or rerun with -SkipAzureRbac."
    }

    $originalAzContext = Get-AzContext
    if ($null -eq $originalAzContext) {
        throw 'Azure RBAC auditing was requested, but no active Az context was found. Connect using existing approved access, or rerun with -SkipAzureRbac.'
    }

    if (@($SubscriptionId).Count -gt 0) {
        foreach ($requestedSubscriptionId in $SubscriptionId) {
            try {
                $auditedSubscriptions += Get-AzSubscription -SubscriptionId $requestedSubscriptionId -ErrorAction Stop
            } catch {
                $warnings.Add([pscustomobject]@{ DataSet='Azure subscriptions'; Message="Subscription $requestedSubscriptionId could not be resolved: $($_.Exception.Message)" })
            }
        }
    } else {
        try {
            $auditedSubscriptions = @(Get-AzSubscription -ErrorAction Stop | Where-Object State -eq 'Enabled')
        } catch {
            $warnings.Add([pscustomobject]@{ DataSet='Azure subscriptions'; Message="Accessible Azure subscriptions could not be enumerated: $($_.Exception.Message)" })
            $auditedSubscriptions = @()
        }

        # Some Az contexts can access the active subscription even when Get-AzSubscription returns no inventory.
        if (@($auditedSubscriptions).Count -eq 0 -and $null -ne $originalAzContext.Subscription -and $originalAzContext.Subscription.Id) {
            $auditedSubscriptions = @([pscustomobject]@{
                Id    = [string]$originalAzContext.Subscription.Id
                Name  = [string]$originalAzContext.Subscription.Name
                State = 'Enabled'
            })
            Write-Warning "Get-AzSubscription returned no enabled subscriptions. Falling back to the active Az context subscription $($originalAzContext.Subscription.Name) ($($originalAzContext.Subscription.Id))."
        }
    }

    if (@($auditedSubscriptions).Count -eq 0) {
        $message = 'Azure RBAC was requested, but no Azure subscription could be enumerated or recovered from the active Az context. Azure RBAC coverage is unavailable.'
        $warnings.Add([pscustomobject]@{ DataSet='Azure RBAC coverage'; Message=$message })
        Write-Warning $message
    }

    foreach ($subscription in @($auditedSubscriptions | Sort-Object Id -Unique)) {
        # Use a distinct name because PowerShell variable names are case-insensitive. Using
        # $subscriptionId here would collide with the typed [string[]]$SubscriptionId parameter.
        $currentSubscriptionId = ConvertTo-NormalizedId $subscription.Id
        $subscriptionName = [string]$subscription.Name
        Write-Host "Retrieving Azure RBAC assignments for $subscriptionName ($currentSubscriptionId)..." -ForegroundColor Cyan

        try {
            $null = Set-AzContext -SubscriptionId $currentSubscriptionId -TenantId $graphContext.TenantId -ErrorAction Stop
            $assignments = @(
                Get-AzRoleAssignment -ErrorAction Stop |
                    Where-Object { $HighPrivilegeAzureRoles -contains $_.RoleDefinitionName }
            )
            $successfulAzureSubscriptionAudits.Add($currentSubscriptionId)
        } catch {
            $warnings.Add([pscustomobject]@{ DataSet='Azure RBAC'; Message="Azure RBAC assignments could not be retrieved for $subscriptionName ($currentSubscriptionId): $($_.Exception.Message)" })
            continue
        }

        foreach ($assignment in $assignments) {
            $objectId = ConvertTo-NormalizedId $assignment.ObjectId
            $objectType = [string]$assignment.ObjectType
            $roleName = [string]$assignment.RoleDefinitionName
            $scope = [string]$assignment.Scope
            $assignmentId = [string]$assignment.RoleAssignmentId

            if ($objectType -eq 'User' -or $userById.ContainsKey($objectId)) {
                $evidence = [pscustomobject][ordered]@{
                    Source='AzureRBAC'; AssignmentPath='Direct'; UserId=$objectId; RoleName=$roleName
                    RoleDefinitionId=[string]$assignment.RoleDefinitionId; Scope=$scope; AssignmentId=$assignmentId
                    SourcePrincipalId=$objectId; SourcePrincipalName=[string]$assignment.DisplayName
                    SubscriptionId=$currentSubscriptionId; SubscriptionName=$subscriptionName
                }
                $azureEvidenceRows += $evidence
                Add-UserPrivilegeEvidence -EvidenceByUser $evidenceByUser -UserId $objectId -Evidence $evidence
                continue
            }

            if ($objectType -eq 'Group') {
                $groupUsers = @(Get-GraphGroupTransitiveUsers -GroupId $objectId -Cache $groupUserCache -Warnings $warnings -Headers $advancedHeaders)
                foreach ($groupUser in $groupUsers) {
                    $groupUserId = ConvertTo-NormalizedId (Get-OptionalProperty $groupUser 'id')
                    if ($groupUserId -and -not $userById.ContainsKey($groupUserId)) { $userById[$groupUserId] = $groupUser }
                    $evidence = [pscustomobject][ordered]@{
                        Source='AzureRBAC'; AssignmentPath='ViaGroup'; UserId=$groupUserId; RoleName=$roleName
                        RoleDefinitionId=[string]$assignment.RoleDefinitionId; Scope=$scope; AssignmentId=$assignmentId
                        SourcePrincipalId=$objectId; SourcePrincipalName=[string]$assignment.DisplayName
                        SubscriptionId=$currentSubscriptionId; SubscriptionName=$subscriptionName
                    }
                    $azureEvidenceRows += $evidence
                    Add-UserPrivilegeEvidence -EvidenceByUser $evidenceByUser -UserId $groupUserId -Evidence $evidence
                }
            }
        }
    }

    try {
        $null = Set-AzContext -SubscriptionId $originalAzContext.Subscription.Id -TenantId $originalAzContext.Tenant.Id -ErrorAction Stop
    } catch {
        $warnings.Add([pscustomobject]@{ DataSet='Azure context'; Message="The original Az context could not be restored automatically: $($_.Exception.Message)" })
    }
}

$findingRows = @()
foreach ($userId in @($evidenceByUser.Keys | Sort-Object)) {
    if (-not $userById.ContainsKey($userId)) {
        $warnings.Add([pscustomobject]@{ DataSet='User resolution'; Message="Elevated principal $userId could not be resolved to a user object." })
        continue
    }

    $user = $userById[$userId]
    $accountEnabledValue = Get-OptionalProperty $user 'accountEnabled' $null
    $accountEnabled = if ($null -eq $accountEnabledValue) { '' } else { [bool]$accountEnabledValue }
    if (-not $IncludeDisabledUsers -and $accountEnabled -eq $false) { continue }

    $evidence = @($evidenceByUser[$userId])
    $entraEvidence = @($evidence | Where-Object Source -eq 'MicrosoftEntra')
    $azureEvidence = @($evidence | Where-Object Source -eq 'AzureRBAC')

    $findingRows += [pscustomobject][ordered]@{
        UserId                       = $userId
        DisplayName                  = Get-OptionalProperty $user 'displayName'
        UserPrincipalName            = Get-OptionalProperty $user 'userPrincipalName'
        AccountEnabled               = $accountEnabled
        UserType                     = Get-OptionalProperty $user 'userType'
        CreatedDateTimeUtc           = ConvertTo-UtcText (Get-OptionalProperty $user 'createdDateTime')
        EntraPrivilegedRoleCount      = @($entraEvidence | Select-Object RoleName,Scope,SourcePrincipalId -Unique).Count
        EntraPrivilegedRoles          = @($entraEvidence | ForEach-Object { "$($_.RoleName) [$($_.AssignmentPath)]" } | Sort-Object -Unique) -join '; '
        AzureHighPrivilegeRoleCount   = @($azureEvidence | Select-Object RoleName,Scope,SubscriptionId,SourcePrincipalId -Unique).Count
        AzureHighPrivilegeAssignments = @($azureEvidence | ForEach-Object { "$($_.RoleName) @ $($_.Scope) [$($_.AssignmentPath)]" } | Sort-Object -Unique) -join '; '
        EvidenceSources               = @($evidence.Source | Sort-Object -Unique) -join ';'
        ReviewStatus                  = 'ExceedsDefaultUserPermissions'
    }
}

$coverageRows = @(
    foreach ($user in $allUsers) {
        $userId = ConvertTo-NormalizedId (Get-OptionalProperty $user 'id')
        $hasEvidence = $evidenceByUser.ContainsKey($userId)
        [pscustomobject][ordered]@{
            UserId            = $userId
            DisplayName       = Get-OptionalProperty $user 'displayName'
            UserPrincipalName = Get-OptionalProperty $user 'userPrincipalName'
            AccountEnabled    = Get-OptionalProperty $user 'accountEnabled'
            UserType          = Get-OptionalProperty $user 'userType'
            ElevatedEvidence  = $hasEvidence
            EvidenceCount     = if($hasEvidence){@($evidenceByUser[$userId]).Count}else{0}
            CoverageStatus    = if($hasEvidence){'ElevatedPrivilegeFound'}else{'DefaultUserPermissionsOnly'}
        }
    }
)

$evidenceRows = @($entraEvidenceRows + $azureEvidenceRows | Sort-Object UserId,Source,RoleName,Scope,AssignmentId -Unique)
$summary = [pscustomobject][ordered]@{
    AuditGeneratedUtc                 = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    TenantId                         = [string]$graphContext.TenantId
    UsersEvaluated                   = $allUsers.Count
    UsersWithElevatedPrivileges      = $findingRows.Count
    EnabledEntraRoleDefinitions      = @($roleDefinitions | Where-Object { [bool](Get-OptionalProperty $_ 'isEnabled' $true) }).Count
    ActiveEntraRoleAssignments       = $roleAssignments.Count
    EntraUserPrivilegeEvidenceRows   = $entraEvidenceRows.Count
    AzureRbacAuditSkipped            = [bool]$SkipAzureRbac
    AzureRbacCoverageStatus          = if($SkipAzureRbac){'Skipped'}elseif($successfulAzureSubscriptionAudits.Count -eq 0){'Unavailable'}elseif($successfulAzureSubscriptionAudits.Count -lt @($auditedSubscriptions).Count){'Partial'}else{'Completed'}
    AzureSubscriptionsDiscovered     = @($auditedSubscriptions | Sort-Object Id -Unique).Count
    AzureSubscriptionsAudited        = $successfulAzureSubscriptionAudits.Count
    AzureHighPrivilegeEvidenceRows   = $azureEvidenceRows.Count
    HighPrivilegeAzureRoles          = $HighPrivilegeAzureRoles -join ';'
    IncludeDisabledUsers             = [bool]$IncludeDisabledUsers
    WarningCount                     = $warnings.Count
}

$profile = [pscustomobject][ordered]@{
    Summary                    = $summary
    DefaultUserRolePermissions = $defaultRows
    ElevatedUsers              = $findingRows
    PrivilegeEvidence          = $evidenceRows
    Coverage                   = $coverageRows
    Warnings                   = @($warnings)
}

$paths = [ordered]@{
    Json     = "$prefix.json"
    Summary  = "$prefix-summary.csv"
    Defaults = "$prefix-default-user-role-permissions.csv"
    Findings = "$prefix-elevated-users.csv"
    Evidence = "$prefix-privilege-evidence.csv"
    Coverage = "$prefix-coverage.csv"
    Warnings = "$prefix-warnings.csv"
}

$profile | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $paths.Json -Encoding UTF8
$summary | Export-Csv -LiteralPath $paths.Summary -NoTypeInformation -Encoding UTF8
Export-CsvWithHeaders -Rows $defaultRows -Headers @('Setting','Value','Interpretation') -LiteralPath $paths.Defaults
Export-CsvWithHeaders -Rows $findingRows -Headers @('UserId','DisplayName','UserPrincipalName','AccountEnabled','UserType','CreatedDateTimeUtc','EntraPrivilegedRoleCount','EntraPrivilegedRoles','AzureHighPrivilegeRoleCount','AzureHighPrivilegeAssignments','EvidenceSources','ReviewStatus') -LiteralPath $paths.Findings
Export-CsvWithHeaders -Rows $evidenceRows -Headers @('Source','AssignmentPath','UserId','RoleName','RoleDefinitionId','Scope','AssignmentId','SourcePrincipalId','SourcePrincipalName','SubscriptionId','SubscriptionName') -LiteralPath $paths.Evidence
Export-CsvWithHeaders -Rows $coverageRows -Headers @('UserId','DisplayName','UserPrincipalName','AccountEnabled','UserType','ElevatedEvidence','EvidenceCount','CoverageStatus') -LiteralPath $paths.Coverage
Export-CsvWithHeaders -Rows @($warnings) -Headers @('DataSet','Message') -LiteralPath $paths.Warnings

Write-Host ''
Write-Host 'Tenant-wide user privilege audit complete.' -ForegroundColor Green
Write-Host "Users evaluated                      : $($summary.UsersEvaluated)"
Write-Host "Users with elevated privileges       : $($summary.UsersWithElevatedPrivileges)"
Write-Host "Enabled Entra role definitions       : $($summary.EnabledEntraRoleDefinitions)"
Write-Host "Active Entra role assignments        : $($summary.ActiveEntraRoleAssignments)"
Write-Host "Entra user privilege evidence rows   : $($summary.EntraUserPrivilegeEvidenceRows)"
Write-Host "Azure RBAC audit skipped             : $($summary.AzureRbacAuditSkipped)"
Write-Host "Azure RBAC coverage status           : $($summary.AzureRbacCoverageStatus)"
Write-Host "Azure subscriptions discovered       : $($summary.AzureSubscriptionsDiscovered)"
Write-Host "Azure subscriptions audited          : $($summary.AzureSubscriptionsAudited)"
Write-Host "Azure high-privilege evidence rows   : $($summary.AzureHighPrivilegeEvidenceRows)"
Write-Host "Warnings                             : $($summary.WarningCount)"
Write-Host "Elevated users report                : $($paths.Findings)"
Write-Host "Privilege evidence report            : $($paths.Evidence)"
Write-Host "Default permissions report           : $($paths.Defaults)"
Write-Host "Coverage report                      : $($paths.Coverage)"
Write-Host "Governance JSON                      : $($paths.Json)"
Write-Host ''
Write-Host 'Only users with active Entra directory roles or configured high-privilege Azure RBAC assignments appear in the elevated-users report.' -ForegroundColor Yellow
