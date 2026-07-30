#requires -Version 7.0
<#
.SYNOPSIS
Evaluates the user-assignment scope of Microsoft Entra Conditional Access policies.

.DESCRIPTION
Determines whether a specified user is included in or excluded from each Conditional
Access policy through All users, direct user assignment, transitive group membership,
or supported directory-role assignment. The script reports policy state and matching
reasons, but it does not claim that a policy will trigger for every sign-in because
application, platform, location, device, risk, authentication flow, and other runtime
conditions are evaluated separately by Microsoft Entra.

.PARAMETER UserPrincipalName
The exact Microsoft Entra user principal name to evaluate.

.PARAMETER IncludeNonTargeted
Includes policies that do not target the user or explicitly exclude the user. By
default, only policies whose user-assignment scope targets the user are returned.

.PARAMETER OutputCsv
Optional path for a CSV export. No CSV is written when this parameter is omitted.

.EXAMPLE
./Get-ConditionalAccessUserTargeting.ps1 -UserPrincipalName 'alice@contoso.com'

.EXAMPLE
./Get-ConditionalAccessUserTargeting.ps1 'alice@contoso.com' -IncludeNonTargeted -OutputCsv ./ca-user-scope.csv

.NOTES
Required delegated Microsoft Graph scopes:
- Policy.Read.All
- Directory.Read.All

Reading Conditional Access policies also requires an appropriate Microsoft Entra role,
such as Security Reader, Global Reader, Security Administrator, or Conditional Access
Administrator.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$UserPrincipalName,

    [Parameter()]
    [switch]$IncludeNonTargeted,

    [Parameter()]
    [string]$OutputCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredCommands = @(
    'Connect-MgGraph',
    'Get-MgContext',
    'Get-MgUser',
    'Get-MgUserTransitiveMemberOf',
    'Get-MgIdentityConditionalAccessPolicy'
)

foreach ($commandName in $requiredCommands) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required Microsoft Graph command '$commandName' was not found. Install Microsoft.Graph, Microsoft.Graph.Users, and Microsoft.Graph.Identity.SignIns."
    }
}

$requiredScopes = @('Policy.Read.All', 'Directory.Read.All')
$context = Get-MgContext
$mustConnect = $null -eq $context

if (-not $mustConnect) {
    $currentScopes = @($context.Scopes)
    foreach ($scope in $requiredScopes) {
        if ($scope -notin $currentScopes) {
            $mustConnect = $true
            break
        }
    }
}

if ($mustConnect) {
    Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome | Out-Null
}

Write-Host "Resolving user: $UserPrincipalName" -ForegroundColor Cyan
$user = Get-MgUser -UserId $UserPrincipalName -Property Id,DisplayName,UserPrincipalName,UserType -ErrorAction Stop

# Transitive membership is required because Conditional Access group targeting also
# applies through nested groups. The returned collection can include groups and
# directory roles.
$memberships = @(Get-MgUserTransitiveMemberOf -UserId $user.Id -All -Property Id,DisplayName,RoleTemplateId)

$groupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$roleTemplateIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($membership in $memberships) {
    $odataType = [string]$membership.AdditionalProperties['@odata.type']

    if ($odataType -eq '#microsoft.graph.group') {
        [void]$groupIds.Add([string]$membership.Id)
        continue
    }

    if ($odataType -eq '#microsoft.graph.directoryRole') {
        $roleTemplateId = $null

        if ($membership.PSObject.Properties['RoleTemplateId']) {
            $roleTemplateId = [string]$membership.RoleTemplateId
        }

        if ([string]::IsNullOrWhiteSpace($roleTemplateId)) {
            $roleTemplateId = [string]$membership.AdditionalProperties['roleTemplateId']
        }

        if (-not [string]::IsNullOrWhiteSpace($roleTemplateId)) {
            [void]$roleTemplateIds.Add($roleTemplateId)
        }
    }
}

Write-Host "Resolved $($groupIds.Count) transitive group membership(s) and $($roleTemplateIds.Count) active directory-role template ID(s)." -ForegroundColor DarkGray

$policies = @(Get-MgIdentityConditionalAccessPolicy -All)
$results = [System.Collections.Generic.List[object]]::new()

function Find-FirstMatch {
    param(
        [AllowNull()][object[]]$PolicyValues,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$UserValues
    )

    foreach ($value in @($PolicyValues)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$value) -and $UserValues.Contains([string]$value)) {
            return [string]$value
        }
    }

    return $null
}

foreach ($policy in $policies) {
    $users = $policy.Conditions.Users

    if ($null -eq $users) {
        $results.Add([pscustomobject]@{
            PolicyName              = $policy.DisplayName
            PolicyId                = $policy.Id
            State                   = $policy.State
            UserScopeResult         = 'NotTargeted'
            IncludedBy              = $null
            ExcludedBy              = $null
            MatchedGroupId          = $null
            MatchedRoleTemplateId   = $null
            RuntimeConditionsRemain = $true
            Notes                   = 'Policy has no user assignment condition.'
        })
        continue
    }

    $includeUsers = @($users.IncludeUsers)
    $excludeUsers = @($users.ExcludeUsers)
    $includeGroups = @($users.IncludeGroups)
    $excludeGroups = @($users.ExcludeGroups)
    $includeRoles = @($users.IncludeRoles)
    $excludeRoles = @($users.ExcludeRoles)

    $matchedIncludeGroup = Find-FirstMatch -PolicyValues $includeGroups -UserValues $groupIds
    $matchedExcludeGroup = Find-FirstMatch -PolicyValues $excludeGroups -UserValues $groupIds
    $matchedIncludeRole = Find-FirstMatch -PolicyValues $includeRoles -UserValues $roleTemplateIds
    $matchedExcludeRole = Find-FirstMatch -PolicyValues $excludeRoles -UserValues $roleTemplateIds

    $includedBy = $null
    if ($includeUsers -contains 'All') {
        $includedBy = 'AllUsers'
    }
    elseif ($includeUsers -contains $user.Id) {
        $includedBy = 'DirectUser'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($matchedIncludeGroup)) {
        $includedBy = 'TransitiveGroup'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($matchedIncludeRole)) {
        $includedBy = 'DirectoryRole'
    }

    # Guest/external-user targeting is more complex than a simple userType check
    # because policies can select specific external identity types and tenants.
    $guestTargetingPresent = $null -ne $users.IncludeGuestsOrExternalUsers

    $excludedBy = $null
    if ($excludeUsers -contains 'All') {
        $excludedBy = 'AllUsers'
    }
    elseif ($excludeUsers -contains $user.Id) {
        $excludedBy = 'DirectUser'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($matchedExcludeGroup)) {
        $excludedBy = 'TransitiveGroup'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($matchedExcludeRole)) {
        $excludedBy = 'DirectoryRole'
    }

    $userScopeResult = if (-not [string]::IsNullOrWhiteSpace($excludedBy)) {
        'Excluded'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($includedBy)) {
        'Targeted'
    }
    elseif ($guestTargetingPresent -and [string]$user.UserType -eq 'Guest') {
        'ReviewGuestOrExternalUserTargeting'
    }
    else {
        'NotTargeted'
    }

    $notes = switch ($userScopeResult) {
        'Targeted' { 'User is within the policy user-assignment scope. Other policy conditions still determine whether a sign-in triggers the policy.' }
        'Excluded' { 'User matches an explicit user, group, role, or All users exclusion.' }
        'ReviewGuestOrExternalUserTargeting' { 'Policy contains guest/external-user targeting that requires tenant and external-user-type evaluation.' }
        default { 'No matching direct user, transitive group, or active directory-role inclusion was found.' }
    }

    $results.Add([pscustomobject]@{
        PolicyName              = $policy.DisplayName
        PolicyId                = $policy.Id
        State                   = $policy.State
        UserScopeResult         = $userScopeResult
        IncludedBy              = $includedBy
        ExcludedBy              = $excludedBy
        MatchedGroupId          = if ($includedBy -eq 'TransitiveGroup') { $matchedIncludeGroup } elseif ($excludedBy -eq 'TransitiveGroup') { $matchedExcludeGroup } else { $null }
        MatchedRoleTemplateId   = if ($includedBy -eq 'DirectoryRole') { $matchedIncludeRole } elseif ($excludedBy -eq 'DirectoryRole') { $matchedExcludeRole } else { $null }
        RuntimeConditionsRemain = $true
        Notes                   = $notes
    })
}

$output = if ($IncludeNonTargeted) {
    @($results)
}
else {
    @($results | Where-Object UserScopeResult -eq 'Targeted')
}

$output = @($output | Sort-Object State, PolicyName)

Write-Host ''
Write-Host "User: $($user.DisplayName) <$($user.UserPrincipalName)>" -ForegroundColor Green
Write-Host "Policies evaluated: $($policies.Count)"
Write-Host "User-scope targeted: $(@($results | Where-Object UserScopeResult -eq 'Targeted').Count)"
Write-Host "Explicitly excluded: $(@($results | Where-Object UserScopeResult -eq 'Excluded').Count)"
Write-Host ''

if ($output.Count -gt 0) {
    $output |
        Select-Object PolicyName, State, UserScopeResult, IncludedBy, ExcludedBy, RuntimeConditionsRemain |
        Format-Table -AutoSize -Wrap
}
else {
    Write-Host 'No Conditional Access policies target this user through the evaluated user-assignment methods.' -ForegroundColor Yellow
}

if (-not [string]::IsNullOrWhiteSpace($OutputCsv)) {
    $parentDirectory = Split-Path -Parent $OutputCsv
    if (-not [string]::IsNullOrWhiteSpace($parentDirectory)) {
        New-Item -Path $parentDirectory -ItemType Directory -Force | Out-Null
    }

    $output | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding utf8
    Write-Host "CSV report saved to: $OutputCsv" -ForegroundColor Cyan
}

Write-Host ''
Write-Host 'Important: This is a user-assignment scope analysis, not a simulation of a specific sign-in. Use the Conditional Access What If tool or sign-in logs to evaluate application, device, location, risk, client type, and other runtime conditions.' -ForegroundColor Yellow
