# Remove M365 Licenses from Disabled Users (patched)
# - Reuses original Connect-MgGraph flow
# - Resolves license names via licenseDetails and group assignedLicenses
# - Builds CSV with DisplayName, UserPrincipalName, Source, License1..N
# - Preserves DryRun behavior (default = $true)

# Set to $true to simulate, $false to actually remove licenses
$DryRun = $true

# Optional CSV export path (set to $null to skip export)
$ExportCsv = ".\disabled_licenses_with_names.csv"

# Required Graph scopes (same as original)
$Scopes = @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All"
)

# Connect to Microsoft Graph (same as original)
Connect-MgGraph -Scopes $Scopes

Write-Host "`nFetching disabled users..." -ForegroundColor Cyan

# Get all disabled users (do not filter by AssignedLicenses here; we'll detect licenses later)
$DisabledUsers = Get-MgUser -All `
    -Filter "accountEnabled eq false" `
    -Property Id,DisplayName,UserPrincipalName

if (-not $DisabledUsers -or $DisabledUsers.Count -eq 0) {
    Write-Host "No disabled users found." -ForegroundColor Green
    return
}

# Build SKU maps for name resolution (best-effort)
$guidToPart = @{}
$acctToPart = @{}
try {
    $skus = Get-MgSubscribedSku -All -ErrorAction Stop
    foreach ($s in $skus) {
        if ($s.SkuId) { $guidToPart[$s.SkuId.Guid.ToString().Trim('{}')] = $s.SkuPartNumber }
        if ($s.AccountSkuId) { $acctToPart[$s.AccountSkuId] = $s.SkuPartNumber }
        if ($s.SkuPartNumber) {
            $guidToPart[$s.SkuPartNumber] = $s.SkuPartNumber
            $acctToPart[$s.SkuPartNumber] = $s.SkuPartNumber
        }
    }
} catch {
    Write-Host "Warning: Could not enumerate subscribed SKUs: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Container for CSV/export
$ExportRows = @()

Write-Host "`nProcessing users (this may take a while)..." -ForegroundColor Cyan
$counter = 0

foreach ($User in $DisabledUsers) {
    $counter++
    if ($counter % 200 -eq 0) { Write-Host "Processed $counter users..." -ForegroundColor Cyan }

    $licenseNames = @()
    $source = ""

    # 1) Try licenseDetails (effective licenses)
    try {
        $ld = Get-MgUserLicenseDetail -UserId $User.Id -ErrorAction Stop
    } catch {
        $ld = @()
    }

    if ($ld -and $ld.Count -gt 0) {
        $licenseNames = $ld | ForEach-Object { $_.SkuPartNumber } | Where-Object { $_ } | Select-Object -Unique
        $source = "licenseDetails"
    } else {
        # 2) Fallback: check group-based licensing via transitive memberOf
        try {
            $memberOf = Get-MgUserMemberOf -UserId $User.Id -All -ErrorAction Stop
        } catch {
            $memberOf = @()
        }

        if ($memberOf -and $memberOf.Count -gt 0) {
            foreach ($m in $memberOf) {
                # Only inspect groups; memberOf can include directory roles, etc.
                $isGroup = $false
                if ($m.AdditionalProperties.ContainsKey('@odata.type')) {
                    $odata = $m.AdditionalProperties['@odata.type']
                    if ($odata -like '*group*') { $isGroup = $true }
                }
                if (-not $isGroup -and $m.PSObject.Properties.Match('DisplayName').Count -gt 0 -and $m.PSObject.Properties.Match('Id').Count -gt 0) {
                    $isGroup = $true
                }

                if ($isGroup) {
                    $groupId = $m.Id
                    if (-not $groupId) { continue }
                    try {
                        $g = Get-MgGroup -GroupId $groupId -Property "displayName,assignedLicenses" -ErrorAction Stop
                    } catch {
                        continue
                    }
                    $gAssigned = $null
                    if ($g.AdditionalProperties.ContainsKey('assignedLicenses')) { $gAssigned = $g.AdditionalProperties['assignedLicenses'] }
                    if ($gAssigned -and $gAssigned.Count -gt 0) {
                        foreach ($gal in $gAssigned) {
                            $resolved = $null
                            if ($null -ne $gal.skuId) {
                                $gid = $gal.skuId.ToString().Trim('{}')
                                if ($guidToPart.ContainsKey($gid)) { $resolved = $guidToPart[$gid] }
                            }
                            if (-not $resolved -and $null -ne $gal.skuPartNumber) { $resolved = $gal.skuPartNumber }
                            if (-not $resolved -and $null -ne $gal.accountSkuId) {
                                if ($acctToPart.ContainsKey($gal.accountSkuId)) { $resolved = $acctToPart[$gal.accountSkuId] }
                                else { $resolved = ($gal.accountSkuId -split ':')[-1] }
                            }
                            if (-not $resolved) { $resolved = ($gal | ConvertTo-Json -Compress) }
                            if ($resolved) { $licenseNames += $resolved }
                        }
                    }
                }
            } # end foreach memberOf

            if ($licenseNames.Count -gt 0) {
                $licenseNames = $licenseNames | Select-Object -Unique
                $source = "groupAssigned (memberOf)"
            }
        } # end if memberOf
    } # end fallback

    # If we discovered license names, proceed (matches original behavior of only acting on users with licenses)
    if ($licenseNames.Count -gt 0) {
        # Prepare license ids for removal if needed (original removed AssignedLicenses.SkuId)
        # Try to get AssignedLicenses.SkuId from user object (may be empty for group-assigned)
        $assignedSkuIds = @()
        try {
            $uWithAssigned = Get-MgUser -UserId $User.Id -Property "assignedLicenses" -ErrorAction Stop
            if ($uWithAssigned.AdditionalProperties.ContainsKey('assignedLicenses')) {
                $als = $uWithAssigned.AdditionalProperties['assignedLicenses']
                foreach ($al in $als) {
                    if ($al.skuId) { $assignedSkuIds += $al.skuId.ToString().Trim('{}') }
                }
            }
        } catch {
            # ignore
        }

        # If no assignedSkuIds (group-assigned), we cannot remove via Set-MgUserLicense (removal of group assignment requires group change)
        if ($DryRun) {
            if ($assignedSkuIds.Count -gt 0) {
                Write-Host "[DRY RUN] Would remove $($assignedSkuIds.Count) license(s) from $($User.UserPrincipalName) (source: $source)" -ForegroundColor Yellow
            } else {
                Write-Host "[DRY RUN] User $($User.UserPrincipalName) has licenses via $source; no direct AssignedLicenses to remove (group-assigned)" -ForegroundColor Yellow
            }
        } else {
            if ($assignedSkuIds.Count -gt 0) {
                try {
                    Set-MgUserLicense `
                        -UserId $User.Id `
                        -AddLicenses @() `
                        -RemoveLicenses $assignedSkuIds
                    Write-Host "Removed $($assignedSkuIds.Count) license(s) from $($User.UserPrincipalName)" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to remove licenses for $($User.UserPrincipalName): $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "Skipping removal for $($User.UserPrincipalName) because licenses are group-assigned (modify group assignments instead)" -ForegroundColor Yellow
            }
        }

        # Add row for CSV/export
        $ExportRows += [PSCustomObject]@{
            DisplayName = $User.DisplayName
            UserPrincipalName = $User.UserPrincipalName
            Source = $source
            LicenseNames = ,($licenseNames)  # store as array for later expansion
        }
    }
}

Write-Host "`nProcessing complete." -ForegroundColor Cyan

# Build CSV-ready objects with License1..N columns
if ($ExportRows.Count -gt 0 -and $ExportCsv) {
    $max = ($ExportRows | ForEach-Object { $_.LicenseNames.Count } | Measure-Object -Maximum).Maximum
    if (-not $max) { $max = 0 }

    $csvOutput = foreach ($r in $ExportRows) {
        $props = @{
            DisplayName = $r.DisplayName
            UserPrincipalName = $r.UserPrincipalName
            Source = $r.Source
        }
        for ($i = 0; $i -lt $max; $i++) {
            $col = "License$([int]($i+1))"
            $props[$col] = if ($i -lt $r.LicenseNames.Count) { $r.LicenseNames[$i] } else { "" }
        }
        [PSCustomObject]$props
    }

    try {
        $csvOutput | Export-Csv -Path $ExportCsv -NoTypeInformation -Force
        Write-Host "`nExported results to ${ExportCsv}" -ForegroundColor Green
    } catch {
        Write-Host "Failed to export CSV to ${ExportCsv}: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "No license-bearing disabled users discovered or CSV export disabled." -ForegroundColor Yellow
}

Write-Host "`nScript completed." -ForegroundColor Cyan