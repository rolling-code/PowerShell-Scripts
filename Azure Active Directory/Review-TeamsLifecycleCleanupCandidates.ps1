# Review-TeamsLifecycleCleanupCandidates.ps1
# Purpose:
#   Read-only Microsoft Teams lifecycle hygiene review.
#   Identifies Teams with:
#     - No members
#     - No enabled members / only disabled members
#     - Disabled members present
#     - External members present
#     - Excessive owners
#     - No owners / no enabled owners
#
# Output:
#   TeamsLifecycleCleanupCandidates.csv
#
# This script does NOT delete, archive, or modify anything.

param(
    [int]$OwnerThreshold = 5,
    [string]$OutputPath = ".\TeamsLifecycleCleanupCandidates.csv"
)

$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor DarkGray
}

function Write-Ok {
    param([string]$Text)
    Write-Host "[OK] $Text" -ForegroundColor Green
}

function Write-Info {
    param([string]$Text)
    Write-Host "[INFO] $Text" -ForegroundColor Gray
}

function Write-Warn {
    param([string]$Text)
    Write-Host "[WARN] $Text" -ForegroundColor Yellow
}

function Write-Bad {
    param([string]$Text)
    Write-Host "[REVIEW] $Text" -ForegroundColor Red
}

Write-Section "Connecting to Microsoft Graph"

Connect-MgGraph -Scopes `
    "Group.Read.All",
    "Directory.Read.All",
    "User.Read.All"


$ctx = Get-MgContext
Write-Ok "Connected to tenant: $($ctx.TenantId)"

Write-Section "Retrieving Microsoft Teams-backed groups"

# Teams are Microsoft 365 Groups with resourceProvisioningOptions containing "Team"
$uri = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$select=id,displayName,createdDateTime,visibility,resourceProvisioningOptions&`$top=999"

$allTeams = @()

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -Headers @{ConsistencyLevel = "eventual"}
    $allTeams += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

Write-Ok "Teams found: $($allTeams.Count)"

Write-Section "Reviewing Team membership and ownership"

$results = New-Object System.Collections.Generic.List[object]
$counter = 0

foreach ($team in $allTeams) {
    $counter++
    Write-Host "[$counter/$($allTeams.Count)] Reviewing: $($team.displayName)" -ForegroundColor Cyan

    $membersUri = "https://graph.microsoft.com/v1.0/groups/$($team.id)/members/microsoft.graph.user?`$select=id,displayName,userPrincipalName,accountEnabled,userType&`$top=999"
    $ownersUri  = "https://graph.microsoft.com/v1.0/groups/$($team.id)/owners/microsoft.graph.user?`$select=id,displayName,userPrincipalName,accountEnabled,userType&`$top=999"

    $members = @()
    $owners = @()

    try {
        do {
            $mResp = Invoke-MgGraphRequest -Method GET -Uri $membersUri
            $members += $mResp.value
            $membersUri = $mResp.'@odata.nextLink'
        } while ($membersUri)
    }
    catch {
        Write-Warn "Could not retrieve members for $($team.displayName): $($_.Exception.Message)"
    }

    try {
        do {
            $oResp = Invoke-MgGraphRequest -Method GET -Uri $ownersUri
            $owners += $oResp.value
            $ownersUri = $oResp.'@odata.nextLink'
        } while ($ownersUri)
    }
    catch {
        Write-Warn "Could not retrieve owners for $($team.displayName): $($_.Exception.Message)"
    }

    $memberCount = $members.Count
    $enabledMembers = @($members | Where-Object { $_.accountEnabled -eq $true })
    $disabledMembers = @($members | Where-Object { $_.accountEnabled -eq $false })
    $guestMembers = @($members | Where-Object { $_.userType -eq "Guest" })

    $ownerCount = $owners.Count
    $enabledOwners = @($owners | Where-Object { $_.accountEnabled -eq $true })
    $disabledOwners = @($owners | Where-Object { $_.accountEnabled -eq $false })

    $findings = New-Object System.Collections.Generic.List[string]
    $recommendedAction = New-Object System.Collections.Generic.List[string]

    if ($memberCount -eq 0) {
        $findings.Add("NoMembers")
        $recommendedAction.Add("Move to cleanup review; likely archive/delete candidate after owner validation")
    }

    if ($memberCount -gt 0 -and $enabledMembers.Count -eq 0) {
        $findings.Add("NoEnabledMembers")
        $recommendedAction.Add("Move to cleanup review; all members are disabled/blocked")
    }

    if ($disabledMembers.Count -gt 0 -and $enabledMembers.Count -gt 0) {
        $findings.Add("DisabledMembersPresent")
        $recommendedAction.Add("Review and remove disabled users from membership")
    }

    if ($ownerCount -eq 0) {
        $findings.Add("NoOwners")
        $recommendedAction.Add("Assign valid owner or archive/delete after validation")
    }

    if ($ownerCount -gt 0 -and $enabledOwners.Count -eq 0) {
        $findings.Add("NoEnabledOwners")
        $recommendedAction.Add("Assign an enabled owner or archive/delete after validation")
    }

    if ($ownerCount -gt $OwnerThreshold) {
        $findings.Add("ExcessiveOwners")
        $recommendedAction.Add("Review owner list and reduce to required owners")
    }

    if ($guestMembers.Count -gt 0) {
        $findings.Add("ExternalMembersPresent")
        $recommendedAction.Add("Validate external access and remove stale guests")
    }

    if ($findings.Count -eq 0) {
        $findings.Add("NoIssueFromThisCheck")
        $recommendedAction.Add("No cleanup action from membership/owner state")
    }

    $severity = "Info"

    if ($findings -contains "NoMembers" -or $findings -contains "NoEnabledMembers" -or $findings -contains "NoOwners" -or $findings -contains "NoEnabledOwners") {
        $severity = "High"
        Write-Bad "$($team.displayName): $($findings -join ', ')"
    }
    elseif ($findings -contains "ExternalMembersPresent" -or $findings -contains "ExcessiveOwners" -or $findings -contains "DisabledMembersPresent") {
        $severity = "Medium"
        Write-Warn "$($team.displayName): $($findings -join ', ')"
    }
    else {
        Write-Ok "$($team.displayName): no membership/ownership issue from this check"
    }

    $results.Add([PSCustomObject]@{
        TeamName              = $team.displayName
        TeamId                = $team.id
        CreatedDateTime       = $team.createdDateTime
        Visibility            = $team.visibility
        MemberCount           = $memberCount
        EnabledMemberCount    = $enabledMembers.Count
        DisabledMemberCount   = $disabledMembers.Count
        GuestMemberCount      = $guestMembers.Count
        OwnerCount            = $ownerCount
        EnabledOwnerCount     = $enabledOwners.Count
        DisabledOwnerCount    = $disabledOwners.Count
        Findings              = ($findings -join "; ")
        Severity              = $severity
        RecommendedAction     = (($recommendedAction | Select-Object -Unique) -join "; ")
        MemberUPNs            = (($members | ForEach-Object { $_.userPrincipalName }) -join ", ")
        DisabledMemberUPNs    = (($disabledMembers | ForEach-Object { $_.userPrincipalName }) -join ", ")
        GuestMemberUPNs       = (($guestMembers | ForEach-Object { $_.userPrincipalName }) -join ", ")
        OwnerUPNs             = (($owners | ForEach-Object { $_.userPrincipalName }) -join ", ")
        DisabledOwnerUPNs     = (($disabledOwners | ForEach-Object { $_.userPrincipalName }) -join ", ")
    })
}

Write-Section "Exporting report"

$sorted = $results |
    Sort-Object `
        @{Expression = {
            switch ($_.Severity) {
                "High" { 1 }
                "Medium" { 2 }
                "Info" { 3 }
                default { 4 }
            }
        }},
        TeamName

$sorted | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Ok "Report exported to: $OutputPath"

Write-Section "Summary"

$total = $results.Count
$high = @($results | Where-Object { $_.Severity -eq "High" }).Count
$medium = @($results | Where-Object { $_.Severity -eq "Medium" }).Count
$noMembers = @($results | Where-Object { $_.Findings -match "NoMembers" }).Count
$noEnabledMembers = @($results | Where-Object { $_.Findings -match "NoEnabledMembers" }).Count
$external = @($results | Where-Object { $_.Findings -match "ExternalMembersPresent" }).Count
$manyOwners = @($results | Where-Object { $_.Findings -match "ExcessiveOwners" }).Count

Write-Host "Teams reviewed: " -NoNewline
Write-Host $total -ForegroundColor White

Write-Host "High priority cleanup candidates: " -NoNewline
Write-Host $high -ForegroundColor Red

Write-Host "Medium priority review candidates: " -NoNewline
Write-Host $medium -ForegroundColor Yellow

Write-Host "Teams with no members: " -NoNewline
Write-Host $noMembers -ForegroundColor Red

Write-Host "Teams with no enabled members: " -NoNewline
Write-Host $noEnabledMembers -ForegroundColor Red

Write-Host "Teams with external guests: " -NoNewline
Write-Host $external -ForegroundColor Yellow

Write-Host "Teams with more than $OwnerThreshold owners: " -NoNewline
Write-Host $manyOwners -ForegroundColor Yellow

Write-Host ""
Write-Host "Recommended lifecycle action:" -ForegroundColor Cyan
Write-Host "  1. Validate with Team owner/business sponsor." -ForegroundColor White
Write-Host "  2. Archive inactive/no-member/no-enabled-member Teams first." -ForegroundColor White
Write-Host "  3. Delete later only after retention/business validation." -ForegroundColor White
Write-Host ""
Write-Host "Done." -ForegroundColor Green