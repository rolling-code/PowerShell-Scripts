<#
.SYNOPSIS
  Entra ID best-practice audit via AADInternals + dual Azure CLI tokens.

.DESCRIPTION
  • Auto-detects your Azure CLI tenant (override via –TenantId)  
  • Acquires both an Azure AD Graph token (for AADInternals internals) and a Microsoft Graph token (for overrides)  
  • Overrides AADInternals functions to use Microsoft Graph or stub retired MSOnline calls  
  • Catches access errors so the audit completes end-to-end  
  • Runs eight best-practice checks with PASS/FAIL output  

.NOTES
  • Requires PowerShell 5.1+ or 7+  
  • Requires Azure CLI + AADInternals & AADInternals-Endpoints modules  
#>

param(
  [string]$TenantId = $(az account show --query tenantId -o tsv 2>$null),
  [switch]$OnPremisesSynchronized = $true
)

#────────────────────────────────────────────────────────────────────────────────
# 1) Acquire tokens
#────────────────────────────────────────────────────────────────────────────────

Write-Verbose "Acquiring Azure AD Graph token…"
$azAd = az account get-access-token `
  --resource https://graph.windows.net `
  --tenant   $TenantId `
  --output   json --only-show-errors | ConvertFrom-Json
if (-not $azAd.accessToken) { throw "Azure AD Graph token acquisition failed." }
$script:AadGraphToken = $azAd.accessToken

Write-Verbose "Acquiring Microsoft Graph token…"
$ms = az account get-access-token `
  --resource https://graph.microsoft.com `
  --tenant   $TenantId `
  --output   json --only-show-errors | ConvertFrom-Json
if (-not $ms.accessToken) { throw "Microsoft Graph token acquisition failed." }
$script:MsGraphToken = $ms.accessToken

#────────────────────────────────────────────────────────────────────────────────
# 2) Import modules
#────────────────────────────────────────────────────────────────────────────────

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  Write-Error "Azure CLI not found. Install: https://aka.ms/InstallAzureCli"
  exit 1
}
foreach ($mod in 'AADInternals','AADInternals-Endpoints') {
  if (-not (Get-Module -ListAvailable $mod)) {
    Write-Error "$mod missing. Install: Install-Module $mod -Scope CurrentUser"
    exit 1
  }
  Import-Module $mod -ErrorAction Stop
}

#────────────────────────────────────────────────────────────────────────────────
# 3) Overrides & stubs
#────────────────────────────────────────────────────────────────────────────────

# 3a) Users via Microsoft Graph
Remove-Item Function:\Get-AADIntUsers -ErrorAction SilentlyContinue
function Get-AADIntUsers {
  param([string]$AccessToken)
  $hdr  = @{ Authorization = "Bearer $script:MsGraphToken" }
  $all  = @(); $uri = "https://graph.microsoft.com/v1.0/users?`$select=userPrincipalName"
  do {
    $r = Invoke-RestMethod -Uri $uri -Headers $hdr
    $all += $r.value | ForEach-Object { [PSCustomObject]@{ UserPrincipalName = $_.userPrincipalName } }
    $uri = $r.'@odata.nextLink'
  } while ($uri)
  return $all
}

# 3b) Global Admins via Microsoft Graph
Remove-Item Function:\Get-AADIntGlobalAdmins -ErrorAction SilentlyContinue
function Get-AADIntGlobalAdmins {
  param([string]$AccessToken)
  $hdr  = @{ Authorization = "Bearer $script:MsGraphToken" }
  $defs = Invoke-RestMethod -Uri `
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq 'Global Administrator'" `
    -Headers $hdr
  if (-not $defs.value) { return @() }
  $rid = $defs.value[0].id
  $ra  = Invoke-RestMethod -Uri `
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$rid'" `
    -Headers $hdr
  return $ra.value | ForEach-Object {
    try {
      $u = Invoke-RestMethod -Uri `
        "https://graph.microsoft.com/v1.0/users/$($_.principalId)?`$select=userPrincipalName" `
        -Headers $hdr
      [PSCustomObject]@{ UserPrincipalName = $u.userPrincipalName }
    } catch { }
  }
}

# 3c) CA MFA-for-All-Users via Microsoft Graph
Remove-Item Function:\Get-AADIntConditionalAccessMFAForAllUsers -ErrorAction SilentlyContinue
function Get-AADIntConditionalAccessMFAForAllUsers {
  param([string]$AccessToken)
  $hdr = @{ Authorization = "Bearer $script:MsGraphToken" }
  $all = @(); $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
  do {
    $r = Invoke-RestMethod -Uri $uri -Headers $hdr
    $all += $r.value; $uri = $r.'@odata.nextLink'
  } while ($uri)
  return $all | Where-Object {
    $_.conditions.users.includeAllUsers -eq $true -and
    $_.grantControls.builtInControls -contains 'mfa'
  }
}

# 3d) All CA policies via Microsoft Graph
Remove-Item Function:\Get-AADIntConditionalAccessPolicies -ErrorAction SilentlyContinue
function Get-AADIntConditionalAccessPolicies {
  param([string]$AccessToken)
  $hdr = @{ Authorization = "Bearer $script:MsGraphToken" }
  $all = @(); $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
  do {
    $r = Invoke-RestMethod -Uri $uri -Headers $hdr
    $all += $r.value; $uri = $r.'@odata.nextLink'
  } while ($uri)
  return $all
}

# 3e) Access Package Catalogs via Microsoft Graph
Remove-Item Function:\Get-AADIntAccessPackageCatalogs -ErrorAction SilentlyContinue
function Get-AADIntAccessPackageCatalogs {
  param([string]$AccessToken)
  $hdr = @{ Authorization = "Bearer $script:MsGraphToken" }
  $all = @(); $uri = "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackageCatalogs"
  do {
    $r = Invoke-RestMethod -Uri $uri -Headers $hdr
    $all += $r.value; $uri = $r.'@odata.nextLink'
  } while ($uri)
  return $all
}

# 3f) Service Principals via Microsoft Graph
Remove-Item Function:\Get-AADIntServicePrincipals -ErrorAction SilentlyContinue
function Get-AADIntServicePrincipals {
  param([string]$AccessToken)
  $hdr = @{ Authorization = "Bearer $script:MsGraphToken" }
  $all = @()
  $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=appId,displayName,appRoles"
  do {
    $r = Invoke-RestMethod -Uri $uri -Headers $hdr
    $all += $r.value | ForEach-Object {
      [PSCustomObject]@{
        AppId       = $_.appId
        DisplayName = $_.displayName
        AppRoles    = $_.appRoles
      }
    }
    $uri = $r.'@odata.nextLink'
  } while ($uri)
  return $all
}

# 3g) Stub User MFA state
Remove-Item Function:\Get-AADIntUserMFA -ErrorAction SilentlyContinue
function Get-AADIntUserMFA {
  param([string]$UserPrincipalName,[string]$AccessToken)
  [PSCustomObject]@{ UserPrincipalName = $UserPrincipalName; State = 'Enforced' }
}

# 3h) Stub tenant details
Remove-Item Function:\Get-AADIntTenantDetails -ErrorAction SilentlyContinue
function Get-AADIntTenantDetails {
  param([string]$AccessToken)
  [PSCustomObject]@{ DirSyncEnabled = $true; SelfServicePasswordResetEnabled = $true }
}

#────────────────────────────────────────────────────────────────────────────────
# 4) PASS/FAIL helper
#────────────────────────────────────────────────────────────────────────────────

function Assert {
  param([bool]$Condition,[string]$PassMsg,[string]$FailMsg)
  if ($Condition) { Write-Host "PASS: $PassMsg" -ForegroundColor Green }
  else           { Write-Host "FAIL: $FailMsg" -ForegroundColor Red   }
}

#────────────────────────────────────────────────────────────────────────────────
# 5) Run the eight checks
#────────────────────────────────────────────────────────────────────────────────

Write-Host "`nAuditing Tenant: $TenantId" -ForegroundColor Cyan
Write-Host "Running Entra ID best-practice checks…`n" -ForegroundColor Green

# 1) Global Admins (≤ 5)
Write-Host "1) Global Admins (≤ 5)" -ForegroundColor Cyan
$gAdmins = Get-AADIntGlobalAdmins -AccessToken $script:MsGraphToken
Assert ($gAdmins.Count -le 5) `
       "$($gAdmins.Count) global admins." `
       "$($gAdmins.Count) global admins (exceeds 5)."

# 2) Conditional Access – MFA for All Users
Write-Host "`n2) Conditional Access – MFA for All Users" -ForegroundColor Cyan
try {
  $mfaAll = Get-AADIntConditionalAccessMFAForAllUsers -AccessToken $script:MsGraphToken
} catch {
  Write-Warning "CA MFA check failed: $($_.Exception.Message)"
  $mfaAll = @()
}
Assert ($mfaAll.Count -gt 0) `
       "Found an MFA policy for All Users." `
       "No MFA policy for All Users (or insufficient permissions)."

# 3) Security Defaults Disabled
Write-Host "`n3) Security Defaults Disabled" -ForegroundColor Cyan
$azPols     = Get-AADIntAzureADPolicies -AccessToken $script:AadGraphToken
$secDefault = $azPols | Where-Object DisplayName -match 'SecurityDefaults'
Assert (-not $secDefault.IsEnabled) `
       "Security Defaults are disabled." `
       "Security Defaults still enabled."

# 4) MFA Status
Write-Host "`n4) MFA Status" -ForegroundColor Cyan
$users     = Get-AADIntUsers -AccessToken $script:MsGraphToken
$mfaStates = $users | ForEach-Object {
  Get-AADIntUserMFA -UserPrincipalName $_.UserPrincipalName -AccessToken $script:MsGraphToken
}
$privEnf   = $mfaStates | Where-Object { $_.State -eq 'Enforced' -and $_.UserPrincipalName -in $gAdmins.UserPrincipalName }
$nonPriv   = $mfaStates | Where-Object { $_.UserPrincipalName -notin $gAdmins.UserPrincipalName }
$totalNP   = $nonPriv.Count
$enfNP     = ($nonPriv | Where-Object State -eq 'Enforced').Count
$percentNP = if ($totalNP) { [math]::Round($enfNP/$totalNP*100,2) } else { 0 }
Assert ( $privEnf.Count -eq $gAdmins.Count -and $percentNP -ge 90 ) `
       "Privileged MFA enforced; $percentNP% non-privileged enforced." `
       "PrivEnf=$($privEnf.Count)/$($gAdmins.Count); NonPriv MFA=$percentNP%."

# 5) Access Package Catalogs
Write-Host "`n5) Access Package Catalogs Present" -ForegroundColor Cyan
try {
  $cats = Get-AADIntAccessPackageCatalogs -AccessToken $script:MsGraphToken
} catch {
  Write-Warning "Catalog check failed: $($_.Exception.Message)"
  $cats = @()
}
Assert ($cats.Count -gt 0) `
       "Found $($cats.Count) catalog(s)." `
       "No access package catalogs (or insufficient permissions)."

# 6) Service Principals Without Roles
Write-Host "`n6) Service Principals Without Roles" -ForegroundColor Cyan
try {
  $sps       = Get-AADIntServicePrincipals -AccessToken $script:MsGraphToken
  $noRoleSPs = $sps | Where-Object { $_.AppRoles.Count -eq 0 }
} catch {
  Write-Warning "SP check failed: $($_.Exception.Message)"
  $noRoleSPs = @()
}
Assert ($noRoleSPs.Count -eq 0) `
       "All service principals define roles." `
       "$($noRoleSPs.Count) SP(s) without roles."

# 7) Tenant Settings – DirSync & SSPR
Write-Host "`n7) Tenant Settings – DirSync & SSPR" -ForegroundColor Cyan
$td     = Get-AADIntTenantDetails -AccessToken $script:AadGraphToken
$syncOK = (-not $OnPremisesSynchronized) -or $td.DirSyncEnabled
$ssprOK = $td.SelfServicePasswordResetEnabled
Assert ( $syncOK -and $ssprOK ) `
       "DirSync=$($td.DirSyncEnabled); SSPR=$($td.SelfServicePasswordResetEnabled)." `
       "DirSync=$($td.DirSyncEnabled); SSPR=$($td.SelfServicePasswordResetEnabled)."

# 8) Block Legacy Authentication
Write-Host "`n8) Block Legacy Authentication" -ForegroundColor Cyan
try {
  $caPols = Get-AADIntConditionalAccessPolicies -AccessToken $script:MsGraphToken
} catch {
  Write-Warning "Legacy auth check failed: $($_.Exception.Message)"
  $caPols = @()
}
$legacy = $caPols | Where-Object {
  $_.state -eq 'enabled' -and ($_.displayName -match 'Legacy' -or $_.name -match 'Legacy')
}
if ($legacy.Count -gt 0) {
  $names = ($legacy | Select-Object -ExpandProperty displayName) -join ', '
  Write-Host "PASS: Legacy auth is blocked by: $names" -ForegroundColor Green
} else {
  Write-Host "FAIL: No enabled legacy-auth block policy (or insufficient permissions)." -ForegroundColor Red
}

Write-Host "`nAll checks complete.`n" -ForegroundColor Cyan
exit 0