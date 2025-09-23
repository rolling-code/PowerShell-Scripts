# Prereq: enum_entra_admins.ps1 CSV created output file
<#
.SYNOPSIS
  Read a CSV of admin-like accounts and report any disabled AD user accounts.

.DESCRIPTION
  - Expects CSV with a column named MemberUPNorAppId containing either a UPN (user@domain) or samAccountName.
  - For each row: if the value looks like a user (contains '@' or does not look like an appId GUID), attempt Get-ADUser.
  - If the AD user exists and Enabled -eq $false, report it and estimate DisabledSince using whenChanged.
  - Outputs a CSV "DisabledAccounts_Report.csv" with details.
#>

param(
    [string]$CsvPath = ".\AdminLikeAccounts_Report.csv",
    [string]$OutputPath = ".\DisabledAccounts_Report.csv"
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Run on a domain-joined machine with RSAT/AD module installed."
    exit 2
}
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV input file not found: $CsvPath"
    exit 3
}

# Read CSV
try {
    $rows = Import-Csv -Path $CsvPath
} catch {
    Write-Error "Failed to read CSV: $_"
    exit 4
}

$results = @()

foreach ($r in $rows) {
    $id = $r.MemberUPNorAppId
    if (-not $id) { continue }

    # Skip obvious non-user values: GUIDs or appId-like (36-char GUID) or empty
    $isGuid = $false
    if ($id -match '^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$') { $isGuid = $true }

    if ($isGuid) {
        # Likely an appId/service principal; skip user lookup
        $results += [pscustomobject]@{
            MemberUPNorAppId = $id
            FoundInAD = $false
            Reason = "GUID-like value (service principal/app) - skipped"
            SamAccountName = ""
            UserPrincipalName = ""
            DisplayName = ""
            Enabled = ""
            DisabledSinceEstimate = ""
            WhenChanged = ""
            WhenCreated = ""
            LastLogon = ""
        }
        continue
    }

    # Determine search key: if contains '@' treat as UPN, otherwise search samAccountName or sAMAccountName
    $adUser = $null
    try {
        if ($id -like '*@*') {
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$id'" -Properties Enabled,whenChanged,whenCreated,lastLogonTimestamp,displayName,sAMAccountName,userPrincipalName -ErrorAction SilentlyContinue
            if (-not $adUser) {
                # fallback to mail or sAMAccountName
                $adUser = Get-ADUser -Filter "Mail -eq '$id' -or sAMAccountName -eq '$id'" -Properties Enabled,whenChanged,whenCreated,lastLogonTimestamp,displayName,sAMAccountName,userPrincipalName -ErrorAction SilentlyContinue
            }
        } else {
            $adUser = Get-ADUser -Filter "sAMAccountName -eq '$id' -or UserPrincipalName -eq '$id'" -Properties Enabled,whenChanged,whenCreated,lastLogonTimestamp,displayName,sAMAccountName,userPrincipalName -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning "Lookup error for '$id': $_"
    }

    if (-not $adUser) {
        $results += [pscustomobject]@{
            MemberUPNorAppId = $id
            FoundInAD = $false
            Reason = "Not found in AD"
            SamAccountName = ""
            UserPrincipalName = ""
            DisplayName = ""
            Enabled = ""
            DisabledSinceEstimate = ""
            WhenChanged = ""
            WhenCreated = ""
            LastLogon = ""
        }
        continue
    }

    # Convert lastLogonTimestamp if present
    $lastLogon = ""
    if ($adUser.lastLogonTimestamp) {
        # lastLogonTimestamp is large integer; use [DateTime] conversion helper
        $lastLogon = [DateTime]::FromFileTimeUtc($adUser.lastLogonTimestamp)
    }

    # If account is disabled, estimate DisabledSince from whenChanged (best-effort)
    $disabledSince = ""
    $reason = ""
    if ($adUser.Enabled -eq $false) {
        # whenChanged is the best available timestamp for change events; if it's close to whenCreated it might be creation date
        if ($adUser.whenChanged) {
            $disabledSince = [DateTime]::Parse($adUser.whenChanged).ToString("u")
            $reason = "Account disabled (estimated from whenChanged)"
        } else {
            $disabledSince = ""
            $reason = "Account disabled (no whenChanged available)"
        }
    } else {
        $reason = "Account enabled"
    }

    $results += [pscustomobject]@{
        MemberUPNorAppId = $id
        FoundInAD = $true
        Reason = $reason
        SamAccountName = $adUser.sAMAccountName
        UserPrincipalName = $adUser.UserPrincipalName
        DisplayName = $adUser.DisplayName
        Enabled = $adUser.Enabled
        DisabledSinceEstimate = $disabledSince
        WhenChanged = if ($adUser.whenChanged) { [DateTime]::Parse($adUser.whenChanged).ToString("u") } else { "" }
        WhenCreated = if ($adUser.whenCreated) { [DateTime]::Parse($adUser.whenCreated).ToString("u") } else { "" }
        LastLogon = if ($lastLogon) { $lastLogon.ToString("u") } else { "" }
    }
}

# Filter to only disabled accounts for quick review
$disabled = $results | Where-Object { $_.FoundInAD -eq $true -and $_.Enabled -eq $false }

if ($disabled.Count -gt 0) {
    Write-Host "Disabled accounts found:" -ForegroundColor Yellow
    $disabled | Format-Table MemberUPNorAppId,DisplayName,UserPrincipalName,SamAccountName,DisabledSinceEstimate,WhenChanged,WhenCreated,LastLogon -AutoSize
} else {
    Write-Host "No disabled accounts found among the CSV entries." -ForegroundColor Green
}

# Export full report
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Full report exported to: $OutputPath" -ForegroundColor Cyan