# Report-InactiveGuestUsers-150Days.ps1
# Purpose:
#   Read-only report of Microsoft Entra guest users inactive for more than X days.
#   Exports CSV sorted from oldest sign-in to newest sign-in.
#
# Default threshold: 150 days
# Recommended action output: Block sign-ins for these users after review.
#
# Required Graph scopes:
#   User.Read.All
#   AuditLog.Read.All
#   Directory.Read.All
#
# Notes:
#   - This script does NOT block or delete users.
#   - Last sign-in data depends on signInActivity availability in your tenant/licensing.
#   - Guests with no sign-in date are included as "Never signed in" if older than threshold by CreatedDateTime.

param(
    [int]$InactiveDays = 150,
    [string]$OutputPath = ".\InactiveGuestUsers_150Days.csv"
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
    Write-Host "[ACTION] $Text" -ForegroundColor Red
}

Write-Section "Inactive Microsoft Entra Guest User Report"

$ThresholdDate = (Get-Date).AddDays(-$InactiveDays)

Write-Info "Inactive threshold: $InactiveDays days"
Write-Info "Threshold date: $ThresholdDate"
Write-Info "Output CSV: $OutputPath"

Write-Section "Connecting to Microsoft Graph"

Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","Directory.Read.All" -NoWelcome

$ctx = Get-MgContext
Write-Ok "Connected to tenant: $($ctx.TenantId)"
Write-Info "Scopes: $($ctx.Scopes -join ', ')"

Write-Section "Retrieving guest users"

Write-Info "Querying users where userType eq 'Guest'..."
Write-Info "Retrieving DisplayName, UPN, Mail, CreatedDateTime, AccountEnabled, SignInActivity, ExternalUserState."

$Guests = Get-MgUser `
    -Filter "userType eq 'Guest'" `
    -Property "id,displayName,userPrincipalName,mail,userType,accountEnabled,createdDateTime,externalUserState,signInActivity" `
    -All

Write-Ok "Total guest users found: $($Guests.Count)"

Write-Section "Evaluating inactivity"

$Report = foreach ($Guest in $Guests) {

    $LastSuccessful = $Guest.SignInActivity.LastSuccessfulSignInDateTime
    $LastInteractive = $Guest.SignInActivity.LastSignInDateTime
    $LastNonInteractive = $Guest.SignInActivity.LastNonInteractiveSignInDateTime

    # Prefer LastSuccessfulSignInDateTime when available.
    # Fall back to LastSignInDateTime if LastSuccessfulSignInDateTime is empty.
    $EffectiveLastSignIn = $null

    if ($LastSuccessful) {
        $EffectiveLastSignIn = [datetime]$LastSuccessful
    }
    elseif ($LastInteractive) {
        $EffectiveLastSignIn = [datetime]$LastInteractive
    }

    $CreatedDate = if ($Guest.CreatedDateTime) { [datetime]$Guest.CreatedDateTime } else { $null }

    $Inactive = $false
    $DaysSinceLastSignIn = $null
    $InactivityReason = $null
    $SortDate = $null

    if ($EffectiveLastSignIn) {
        $DaysSinceLastSignIn = ((Get-Date) - $EffectiveLastSignIn).Days

        if ($EffectiveLastSignIn -lt $ThresholdDate) {
            $Inactive = $true
            $InactivityReason = "Last sign-in older than $InactiveDays days"
            $SortDate = $EffectiveLastSignIn
        }
    }
    else {
        # Never signed in. Include only if account was created before threshold date.
        if ($CreatedDate -and $CreatedDate -lt $ThresholdDate) {
            $Inactive = $true
            $DaysSinceLastSignIn = "Never"
            $InactivityReason = "Never signed in and account older than $InactiveDays days"
            $SortDate = [datetime]"1900-01-01"
        }
    }

    if ($Inactive) {
        [PSCustomObject]@{
            DisplayName                    = $Guest.DisplayName
            UserPrincipalName              = $Guest.UserPrincipalName
            Mail                           = $Guest.Mail
            AccountEnabled                 = $Guest.AccountEnabled
            ExternalUserState              = $Guest.ExternalUserState
            CreatedDateTime                = $CreatedDate
            LastSuccessfulSignInDateTime   = $LastSuccessful
            LastInteractiveSignInDateTime  = $LastInteractive
            LastNonInteractiveSignInDateTime = $LastNonInteractive
            EffectiveLastSignInDateTime    = $EffectiveLastSignIn
            DaysSinceLastSignIn            = $DaysSinceLastSignIn
            InactivityReason               = $InactivityReason
            RecommendedAction              = "Review owner/business need, then block sign-ins"
            ObjectId                       = $Guest.Id
            SortDate                       = $SortDate
        }
    }
}

$ReportSorted = $Report |
    Sort-Object SortDate, DisplayName |
    Select-Object `
        DisplayName,
        UserPrincipalName,
        Mail,
        AccountEnabled,
        ExternalUserState,
        CreatedDateTime,
        LastSuccessfulSignInDateTime,
        LastInteractiveSignInDateTime,
        LastNonInteractiveSignInDateTime,
        EffectiveLastSignInDateTime,
        DaysSinceLastSignIn,
        InactivityReason,
        RecommendedAction,
        ObjectId

Write-Ok "Inactive guest users found: $($ReportSorted.Count)"

Write-Section "Exporting CSV"

if ($ReportSorted.Count -gt 0) {
    $ReportSorted |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Ok "CSV exported successfully:"
    Write-Host "  $OutputPath" -ForegroundColor White
}
else {
    Write-Ok "No inactive guest users found over $InactiveDays days. No CSV rows to export."

    # Still create an empty CSV with headers for audit consistency
    $ReportSorted |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Info "Empty CSV created for audit record:"
    Write-Host "  $OutputPath" -ForegroundColor White
}

Write-Section "Summary"

Write-Host "Guest users evaluated: " -NoNewline
Write-Host $Guests.Count -ForegroundColor White

Write-Host "Inactive threshold: " -NoNewline
Write-Host "$InactiveDays days" -ForegroundColor White

Write-Host "Inactive guest users found: " -NoNewline
if ($ReportSorted.Count -gt 0) {
    Write-Host $ReportSorted.Count -ForegroundColor Red
}
else {
    Write-Host "0" -ForegroundColor Green
}

if ($ReportSorted.Count -gt 0) {
    Write-Bad "Recommended action: Review these users, then block sign-ins for accounts with no current business justification."
    Write-Warn "This script is read-only and did NOT block sign-ins."
    Write-Warn "Do not delete immediately. Recommended lifecycle is: review/attest -> block sign-in -> delete after grace period."
}
else {
    Write-Ok "No action required based on the $InactiveDays-day inactivity threshold."
}

Write-Host ""
Write-Host "Suggested next step:" -ForegroundColor Cyan
Write-Host "  Review the CSV with app/site/group owners. For confirmed stale guests, block sign-in first, then delete later after a grace period." -ForegroundColor White

Write-Host ""
Write-Host "Done." -ForegroundColor Green