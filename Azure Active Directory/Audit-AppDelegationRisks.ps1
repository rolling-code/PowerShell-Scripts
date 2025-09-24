param(
    [Parameter(Mandatory = $true)]
    [string]$TargetAppId
)

# Connect to Graph with scopes already consented in your tenant
Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All" -NoWelcome

# Define high-risk delegated scopes
$highRiskScopes = @(
    # Mailbox / collaboration
    "Calendars.ReadWrite","Contacts.ReadWrite","Mail.Send","Mail.ReadWrite","Mail.Read",
    "Contacts.Read.All","Calendars.Read.All","IMAP.AccessAsUser.All","POP.AccessAsUser.All",
    # Device management / Intune
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementManagedDevices.Read.All",
    "Device.Read.All"
)

# Get the Service Principal
$sp = Get-MgServicePrincipal -Filter "appId eq '$TargetAppId'"

Write-Host "=== Risk Audit for App: $($sp.DisplayName) ($TargetAppId) ===" -ForegroundColor Cyan

# --- Assignment Requirement ---
Write-Host "`n=== Assignment Requirement ===" -ForegroundColor Cyan
$app = Get-MgServicePrincipal -ServicePrincipalId $sp.Id -Property AppRoleAssignmentRequired

if ($app.AppRoleAssignmentRequired -eq $true) {
    Write-Host "User assignment required: YES (only explicitly assigned users/groups can access)" -ForegroundColor Yellow
} else {
    Write-Host "User assignment required: NO (any user in the tenant can access if consent is granted)" -ForegroundColor Red
}

# --- Delegated Permission Grants ---
$grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)'" -All
foreach ($grant in $grants) {
    $scopes = $grant.Scope -split " "
    $risky  = $scopes | Where-Object { $_ -in $highRiskScopes }

    if ($grant.ConsentType -eq "AllPrincipals" -and $risky) {
        Write-Host "[PROBLEM] Tenant-wide delegated grant detected!" -ForegroundColor Red
        Write-Host "ConsentType : $($grant.ConsentType)"
        Write-Host "RiskyScopes : $($risky -join ', ')"
        Write-Host "FullScope   : $($grant.Scope)"
        Write-Host ""
    }
    elseif ($grant.ConsentType -eq "Principal" -and $risky) {
        Write-Host "[INFO] Per-user delegated grant with risky scopes." -ForegroundColor Yellow
        Write-Host "ConsentType : $($grant.ConsentType)"
        Write-Host "RiskyScopes : $($risky -join ', ')"
        Write-Host "FullScope   : $($grant.Scope)"
        Write-Host ""
    }
    else {
        Write-Host "[OK] No high-risk scopes in this grant." -ForegroundColor Green
        Write-Host "ConsentType : $($grant.ConsentType)"
        Write-Host "FullScope   : $($grant.Scope)"
        Write-Host ""
    }
}

# --- Owners ---
Write-Host "=== Owners of this App ===" -ForegroundColor Cyan
$owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -All |
    Select-Object Id, DisplayName, UserPrincipalName

if ($owners) { $owners | Format-Table -AutoSize } else { Write-Host "(none)" }

# --- Assigned Users/Groups (App Role Assignments) ---
Write-Host "`n=== Assigned Users/Groups ===" -ForegroundColor Cyan
$assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All

if ($assignments) {
    $principals = foreach ($a in $assignments) {
        try {
            # Resolve the directory object for each assignment
            $obj = Get-MgDirectoryObject -DirectoryObjectId $a.PrincipalId
            # Cast to the right type if possible
            if ($obj.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.user") {
                [PSCustomObject]@{
                    Id               = $obj.Id
                    Type             = "User"
                    DisplayName      = $obj.AdditionalProperties.displayName
                    UserPrincipalName= $obj.AdditionalProperties.userPrincipalName
                }
            }
            elseif ($obj.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.group") {
                [PSCustomObject]@{
                    Id               = $obj.Id
                    Type             = "Group"
                    DisplayName      = $obj.AdditionalProperties.displayName
                    UserPrincipalName= ""
                }
            }
            elseif ($obj.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.servicePrincipal") {
                [PSCustomObject]@{
                    Id               = $obj.Id
                    Type             = "ServicePrincipal"
                    DisplayName      = $obj.AdditionalProperties.displayName
                    UserPrincipalName= ""
                }
            }
            else {
                [PSCustomObject]@{
                    Id               = $obj.Id
                    Type             = $obj.AdditionalProperties.'@odata.type'
                    DisplayName      = $obj.AdditionalProperties.displayName
                    UserPrincipalName= $obj.AdditionalProperties.userPrincipalName
                }
            }
        }
        catch {
            Write-Warning "Could not resolve object $($a.PrincipalId)"
        }
    }
    if ($principals) { $principals | Format-Table -AutoSize } else { Write-Host "(none resolved)" }
} else {
    Write-Host "(none)"
}

# --- OAuth2 Permission Grants (raw view) ---
Write-Host "`n=== OAuth2 Permission Grants (raw) ===" -ForegroundColor Cyan
$grants | Select-Object Id, ConsentType, Scope | Format-Table -AutoSize