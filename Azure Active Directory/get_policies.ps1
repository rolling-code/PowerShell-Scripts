<#
.SYNOPSIS
  Lists all Conditional Access policies that apply to a given user.

.PARAMETER UserPrincipalName
  The UPN (email) of the user to evaluate.

.EXAMPLE
  .\List-ConditionalAccessPoliciesForUser.ps1 -UserPrincipalName "alice@contoso.com"
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$UserPrincipalName
)

# 1. Ensure Graph module is present
if (-not (Get-Module Microsoft.Graph)) {
  Install-Module Microsoft.Graph -Scope CurrentUser -Force
}
Import-Module Microsoft.Graph

# 2. Connect to Microsoft Graph
Write-Verbose "Connecting to Microsoft Graph..."
Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All"

# 3. Retrieve user object and memberships
$user = Get-MgUser -UserId $UserPrincipalName
$userId = $user.Id

# Fetch all group and role memberships
$memberOf = Get-MgUserMemberOf -UserId $userId -All
$groupIds = $memberOf |
  Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } |
  Select-Object -ExpandProperty Id
$roleIds = $memberOf |
  Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' } |
  Select-Object -ExpandProperty Id

# 4. Pull down every CA policy
$policies = Get-MgIdentityConditionalAccessPolicy -All

# 5. Evaluate each policy’s user filter
$applied = foreach ($pol in $policies) {
  $u = $pol.Conditions.Users

  # Determine inclusion
  $included = $false
  if ($u.IncludeUsers -contains 'All') { $included = $true }
  elseif ($u.IncludeUsers -contains $userId) { $included = $true }
  elseif ($u.IncludeGroups  -contains 'All') { $included = $true }
  elseif ($groupIds | Where-Object { $u.IncludeGroups -contains $_ }) { $included = $true }
  elseif ($u.IncludeRoles   -contains 'All') { $included = $true }
  elseif ($roleIds  | Where-Object { $u.IncludeRoles -contains $_ }) { $included = $true }

  if (-not $included) { continue }

  # Determine exclusion
  $excluded = $false
  if ($u.ExcludeUsers -contains 'All') { $excluded = $true }
  elseif ($u.ExcludeUsers -contains $userId) { $excluded = $true }
  elseif ($u.ExcludeGroups  -contains 'All') { $excluded = $true }
  elseif ($groupIds | Where-Object { $u.ExcludeGroups -contains $_ }) { $excluded = $true }
  elseif ($u.ExcludeRoles   -contains 'All') { $excluded = $true }
  elseif ($roleIds  | Where-Object { $u.ExcludeRoles -contains $_ }) { $excluded = $true }

  if (-not $excluded) {
    [PSCustomObject]@{
      Name  = $pol.DisplayName
      Id    = $pol.Id
      State = $pol.State
    }
  }
}

# 6. Output results
if ($applied) {
  $applied | Sort-Object Name | Format-Table -AutoSize
} else {
  Write-Host "No Conditional Access policies apply to $UserPrincipalName."
}