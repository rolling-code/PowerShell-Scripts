<#
.SYNOPSIS
  Tenant-wide audit of default user role permissions, privileged directory roles, 
  and high-privilege Azure RBAC assignments—highlighting only users who exceed 
  the locked-down defaults.
  Must have Graph API permissions Policy.Read.All to use this script

.DESCRIPTION
  1. Authenticates via device-code flow (MFA-friendly).
  2. Reads tenant defaults from Microsoft Graph (/policies/authorizationPolicy).
  3. Enumerates all users and checks:
     • Membership in any enabled directory role.
     • Assignments of high-privilege RBAC roles (Owner, Contributor, User Access Administrator).
  4. Prints only those users with extra privileges.

.NOTES
  Requires:
    • Az.Accounts  v2.9.0+
    • Az.Resources (for Get-AzRoleAssignment)
    • Delegated Graph scopes: Policy.Read.All, Directory.Read.All
#>

function Unsecure-String {
    param(
        [Parameter(Mandatory)][System.Security.SecureString]$Secure
    )
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# 1. Authenticate if needed
if (-not (Get-AzContext)) {
    Write-Host "→ Signing in to Azure…" -ForegroundColor Yellow
    Connect-AzAccount -UseDeviceAuthentication | Out-Null
}

# 2. Acquire Graph access token
Write-Host "→ Acquiring Microsoft Graph token…" -ForegroundColor Yellow
$gt = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token = if ($gt.Token -is [System.Security.SecureString]) {
    Unsecure-String $gt.Token
} else {
    $gt.Token
}

# 3. Fetch tenant defaultUserRolePermissions
Write-Host "→ Retrieving tenant defaultUserRolePermissions…" -ForegroundColor Yellow
$graphHeaders = @{ Authorization = "Bearer $token" }
$authzUri     = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
$authzPolicy  = Invoke-RestMethod -Method Get -Uri $authzUri -Headers $graphHeaders

if (-not $authzPolicy.defaultUserRolePermissions) {
    throw "Failed to retrieve defaultUserRolePermissions."
}

# Display tenant defaults
Write-Host "`nTenant Default User Role Permissions:`n" -ForegroundColor Cyan
$authzPolicy.defaultUserRolePermissions.PSObject.Properties |
  ForEach-Object {
    $clr = if ([bool]$_.Value) { 'Red' } else { 'Green' }
    Write-Host ("{0,-40}: {1}" -f $_.Name, $_.Value) -ForegroundColor $clr
}

# 4. Helper to page through Graph
function Get-GraphAll {
    param([string]$Path)
    $items = @()
    $uri   = "https://graph.microsoft.com/v1.0$Path"
    do {
        $resp  = Invoke-RestMethod -Method Get -Uri $uri -Headers $graphHeaders
        $items += $resp.value
        $uri    = $resp.'@odata.nextLink'
    } while ($uri)
    return $items
}

# 5. Enumerate all users
Write-Host "`n→ Fetching all users…" -ForegroundColor Yellow
$allUsers = Get-GraphAll "/users?`$select=id,userPrincipalName"

# 6. Directory role memberships
Write-Host "→ Fetching directory roles and members…" -ForegroundColor Yellow
$dirRoles = Get-GraphAll "/directoryRoles?`$select=id,displayName"

# Build a flat list of {UserId, UPN, DirRole}
$members = foreach ($role in $dirRoles) {
    $m = Get-GraphAll "/directoryRoles/$($role.id)/members?`$select=id,userPrincipalName"
    foreach ($u in $m) {
        [PSCustomObject]@{
            UserId  = $u.id
            UPN     = $u.userPrincipalName
            DirRole = $role.displayName
        }
    }
}
# Group by UserId into hashtable (or empty if no members)
$rolesByUser = if ($members) {
    $members | Group-Object -AsHashTable -Property UserId
} else {
    @{}
}

# 7. High-privilege Azure RBAC assignments
$highAZ = 'Owner','Contributor','User Access Administrator'
Write-Host "→ Fetching high-privilege RBAC assignments…" -ForegroundColor Yellow
$rbacRaw = Get-AzRoleAssignment |
    Where-Object { $highAZ -contains $_.RoleDefinitionName } |
    ForEach-Object {
        [PSCustomObject]@{
            UserId = $_.ObjectId
            Role   = $_.RoleDefinitionName
            Scope  = $_.Scope
        }
    }
$rbacByUser = if ($rbacRaw) {
    $rbacRaw | Group-Object -AsHashTable -Property UserId
} else {
    @{}
}

# 8. Report users with extra privileges
Write-Host "`nUsers with additional elevated permissions:`n" -ForegroundColor Cyan
foreach ($u in $allUsers) {
    $uid    = $u.id
    $hasDir = $rolesByUser.ContainsKey($uid)
    $hasRbac= $rbacByUser.ContainsKey($uid)

    if ($hasDir -or $hasRbac) {
        Write-Host $u.userPrincipalName -ForegroundColor Yellow

        if ($hasDir) {
            $names = ($rolesByUser[$uid] | Select-Object -ExpandProperty DirRole) -join ", "
            Write-Host ("  Directory Roles : {0}" -f $names) -ForegroundColor Magenta
        }
        if ($hasRbac) {
            foreach ($a in $rbacByUser[$uid]) {
                Write-Host ("  RBAC Assignment : {0} @ {1}" -f $a.Role, $a.Scope) `
                  -ForegroundColor Magenta
            }
        }
    }
}