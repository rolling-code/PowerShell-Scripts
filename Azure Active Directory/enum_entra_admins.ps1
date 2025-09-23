# Prereq: az CLI installed and az login performed (use an account with Directory Reader / User Reader permissions)

# 1) find groups whose displayName contains "Administrator"
$groups = az --% ad group list --query "[?contains(displayName,'Administrator')].[displayName,id]" --only-show-errors -o json | ConvertFrom-Json

if (-not $groups) {
    Write-Host "No groups found." -ForegroundColor Yellow
    exit 0
}

$results = @()

foreach ($g in $groups) {
    $gName = $g[0]
    $gId   = $g[1]

    Write-Host "Processing group: $gName ($gId)" -ForegroundColor Cyan

    # 2) list members of the group (may return users, service principals, etc.)
    $membersJson = az ad group member list --group $gId -o json 2>$null
    if (-not $membersJson) { continue }
    $members = $membersJson | ConvertFrom-Json

    foreach ($m in $members) {
        # Determine type and UPN or AppId
        $odataType = $m.'@odata.type'
        $userPrincipalName = $null
        $displayName = $null
        $objectId = $m.id

        switch ($odataType) {
            '#microsoft.graph.user' {
                $userPrincipalName = $m.userPrincipalName
                $displayName = $m.displayName
            }
            '#microsoft.graph.servicePrincipal' {
                $userPrincipalName = $m.appId
                $displayName = $m.displayName
            }
            default {
                # fallback
                $displayName = $m.displayName
            }
        }

        # 3) fetch Azure AD user details where applicable (az ad user show)
        $aadUser = $null
        if ($userPrincipalName -and ($userPrincipalName -like '*@*')) {
            try {
                $aadUserJson = az ad user show --id $userPrincipalName -o json 2>$null
                if ($aadUserJson) { $aadUser = $aadUserJson | ConvertFrom-Json }
            } catch { $aadUser = $null }
        }

        # 4) fetch Azure RBAC role assignments for the principal (may return ARM RBAC roles)
        $rbac = @()
        try {
            # Use principal id (object id) for RBAC lookup if available
            if ($objectId) {
                $rbacJson = az role assignment list --assignee-object-id $objectId -o json 2>$null
                if ($rbacJson) { $rbac = $rbacJson | ConvertFrom-Json }
            } elseif ($userPrincipalName) {
                $rbacJson = az role assignment list --assignee $userPrincipalName -o json 2>$null
                if ($rbacJson) { $rbac = $rbacJson | ConvertFrom-Json }
            }
        } catch { $rbac = @() }

        # compose an entry
        $entry = [PSCustomObject]@{
            GroupDisplayName        = $gName
            GroupObjectId           = $gId
            MemberObjectId          = $objectId
            MemberDisplayName       = $displayName
            MemberUPNorAppId        = $userPrincipalName
            AccountEnabled          = if ($aadUser) { $aadUser.accountEnabled } else { $null }
            Mail                    = if ($aadUser) { $aadUser.mail } else { $null }
            JobTitle                = if ($aadUser) { $aadUser.jobTitle } else { $null }
            Department              = if ($aadUser) { $aadUser.department } else { $null }
            CreatedDateTime         = if ($aadUser) { $aadUser.createdDateTime } else { $null }
            AzureRBACRoles          = if ($rbac -and $rbac.Count -gt 0) { ($rbac | ForEach-Object { "$($_.roleDefinitionName)@$($_.scope)" }) -join '; ' } else { "" }
        }

        $results += $entry
    }
}

# Output results to console and CSV
$results | Sort-Object GroupDisplayName, MemberDisplayName | Format-Table -AutoSize

$csvPath = ".\AdminLikeAccounts_Report.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "`nExported report to: $csvPath" -ForegroundColor Green