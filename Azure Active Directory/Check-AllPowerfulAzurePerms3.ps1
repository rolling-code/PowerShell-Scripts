<#
.SYNOPSIS
  Scan every subscription for Sonrai’s “Powerful Permissions in Azure.”

.DESCRIPTION
  - Connects using device code.  
  - Gathers your user’s role assignments per subscription.  
  - Tests each high-risk permission from the six-part Sonrai blog.  
  - Exports findings to CSV and writes colored console messages.

.NOTES
  Requirements:
    - Az.Accounts, Az.Resources modules
    - PowerShell 7+ (for colored output)
#>

# 1. Authenticate
Write-Host "→ Authenticating to Azure (Device Code)…" -ForegroundColor Cyan
Connect-AzAccount -UseDeviceAuthentication | Out-Null

# 2. Identify current user
$currentUpn = (Get-AzContext).Account.Id
$current    = Get-AzADUser -UserPrincipalName $currentUpn
Write-Host "✔ Signed in as $($current.DisplayName) <$currentUpn>`n" `
  -ForegroundColor Green

# 3. Define the Sonrai “Powerful Permissions in Azure”
$checks = @(
  # Part 1
  @{Part=1; Perm='Microsoft.ApiManagement/service/users/write'}
  @{Part=1; Perm='Microsoft.Datadog/monitors/singleSignOnConfigurations/write'}

  # Part 2
  @{Part=2; Perm='Microsoft.Storage/storageAccounts/localusers/write'}

  # Part 3
  @{Part=3; Perm='Microsoft.DataBoxEdge/dataBoxEdgeDevices/users/write'}
  @{Part=3; Perm='Microsoft.Authorization/policyAssignments/exempt/action'}

  # Part 4
  @{Part=4; Perm='Microsoft.Sql/servers/tdeCertificates/action'}
  @{Part=4; Perm='Microsoft.Devices/iotHubs/certificates/write'}

  # Part 5
  @{Part=5; Perm='Microsoft.Automanage/configurationProfileAssignments/delete'}

  # Part 6 (Series Final)
  @{Part=6; Perm='Microsoft.DataMigration/databaseMigrationServices/instanceProfiles/write'}
  @{Part=6; Perm='Microsoft.Maintenance/maintenanceConfigurations/write'}
  @{Part=6; Perm='Microsoft.Maintenance/maintenanceConfigurations/delete'}
)

# 4. Helper: Test if a permission string matches any wildcard grant
function Test-Perm {
  param(
    [string] $Candidate,
    [string[]] $Grants
  )
  foreach ($pattern in $Grants) {
    if ($Candidate -like $pattern) { return $true }
  }
  return $false
}

# 5. Prepare output collection
$results = [System.Collections.Generic.List[PSObject]]::new()

# 6. Iterate all subscriptions
$allSubs = Get-AzSubscription
foreach ($sub in $allSubs) {

  Write-Host "`n▶ Subscription: $($sub.Name) <$($sub.Id)>" `
    -ForegroundColor Cyan

  # Switch context
  Select-AzSubscription -SubscriptionId $sub.Id | Out-Null

  # Fetch role assignments scoped to this subscription
  $assigns = Get-AzRoleAssignment `
    -ObjectId $current.Id `
    -Scope "/subscriptions/$($sub.Id)"

  # Resolve all Actions from assigned role definitions
  $allActions = $assigns |
    ForEach-Object {
      $rid = [Guid]$_.RoleDefinitionId
      (Get-AzRoleDefinition -Id $rid).Permissions.Actions
    } |
    Select-Object -Unique

  # Check each Sonrai permission
  foreach ($c in $checks) {
    $has = Test-Perm -Candidate $c.Perm -Grants $allActions

    if ($has) {
      Write-Warning "[Part $($c.Part)] You CAN perform $($c.Perm)"
    }
    else {
      Write-Host "[Part $($c.Part)] OK: No $($c.Perm)" `
        -ForegroundColor Green
    }

    # Append to results
    $results.Add([PSCustomObject]@{
      SubscriptionName = $sub.Name
      SubscriptionId   = $sub.Id
      Part             = $c.Part
      Permission       = $c.Perm
      HasPermission    = $has
    })
  }
}

# 7. Export to CSV
$csvPath = Join-Path $PWD 'PowerfulPermsReport.csv'
$results | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "`n✓ Report saved to $csvPath" -ForegroundColor Cyan