<#
.SYNOPSIS
  Full profile of a Microsoft Entra application by AppId.

.DESCRIPTION
  Retrieves:
    - App registration details (name, publisher, sign-in audience, URLs)
    - Service principal details
    - Owners
    - Credentials
    - Permissions (delegated & application)
    - Assigned users/groups
    - Tenant-wide delegated grants
    - Recent sign-ins (last 30 days)

.PARAMETER TargetAppId
  The AppId (GUID) of the application to profile.

.NOTES
  Requires Microsoft.Graph and MSAL.PS modules.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetAppId
)

# Connect to Graph
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}
Import-Module Microsoft.Graph

#Connect-MgGraph -Scopes "Application.Read.All","AppRoleAssignment.Read.All","Directory.Read.All","DelegatedPermissionGrant.Read.All","AuditLog.Read.All" -NoWelcome
#Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All","DelegatedPermissionGrant.Read.All","AuditLog.Read.All" -NoWelcome
Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All" -NoWelcome


# Resolve app & SP
$app = Get-MgApplication -Filter "appId eq '$TargetAppId'"
$sp  = Get-MgServicePrincipal -Filter "appId eq '$TargetAppId'"

if (-not $app -or -not $sp) {
    Write-Host "App not found in tenant." -ForegroundColor Red
    return
}

Write-Host "=== Application Profile ===" -ForegroundColor Cyan
Write-Host ("Display Name: {0}" -f $app.DisplayName)
Write-Host ("Publisher: {0}" -f ($app.PublisherDomain ?? "Unknown"))
Write-Host ("Sign-in Audience: {0}" -f $app.SignInAudience)
Write-Host ("App Type: {0}" -f ($app.Web -and $app.Web.HomePageUrl ? "Web app" : "Other"))
Write-Host ("Homepage URL: {0}" -f ($app.Web.HomePageUrl ?? "None"))
Write-Host ("Reply URLs: {0}" -f (($app.Web.RedirectUris) -join ', '))
Write-Host ("Owners: {0}" -f (($app.Owners | ForEach-Object { $_.UserPrincipalName }) -join ', '))
Write-Host ("Has Password Credentials: {0}" -f (($app.PasswordCredentials | Measure-Object).Count -gt 0))
Write-Host ("Has Key Credentials: {0}" -f (($app.KeyCredentials | Measure-Object).Count -gt 0))

Write-Host "`n=== Permissions to Microsoft Graph ===" -ForegroundColor Cyan
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Delegated
$delegatedGrants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)' and resourceId eq '$($graphSp.Id)'" -All
foreach ($g in $delegatedGrants) {
    Write-Host ("Delegated: {0} (ConsentType: {1})" -f $g.Scope, $g.ConsentType) -ForegroundColor Yellow
}

# Application
$appRoleAssignments = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -All | Where-Object { $_.ResourceId -eq $graphSp.Id }
foreach ($a in $appRoleAssignments) {
    $role = ($graphSp.AppRoles | Where-Object { $_.Id -eq $a.AppRoleId }).Value
    Write-Host ("Application: {0}" -f $role) -ForegroundColor Red
}

Write-Host "`n=== Assigned Users/Groups ===" -ForegroundColor Cyan
$assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All
foreach ($assign in $assignments) {
    $principal = Get-MgDirectoryObject -DirectoryObjectId $assign.PrincipalId
    Write-Host ("Assigned: {0}" -f ($principal.AdditionalProperties.displayName ?? $principal.Id))
}

Write-Host "`n=== Recent Sign-ins (last 30 days) ===" -ForegroundColor Cyan
# Calculate date 30 days ago in UTC
$thirtyDaysAgo = (Get-Date).ToUniversalTime().AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")

# Use it in the filter
$signins = Get-MgAuditLogSignIn -All -Filter "appId eq '$TargetAppId' and createdDateTime ge $thirtyDaysAgo"
#$signins = Get-MgAuditLogSignIn -Filter "appId eq '$TargetAppId' and createdDateTime ge $(Get-Date).AddDays(-30).ToString('o')" -All
foreach ($s in $signins) {
    Write-Host ("{0} - {1} from {2}" -f $s.UserDisplayName, $s.CreatedDateTime, $s.ClientAppUsed)
}

Disconnect-MgGraph
Write-Host "=== Profile complete ===" -ForegroundColor Green