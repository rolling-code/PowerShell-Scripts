<#
Group-aware disabled-user license exporter.
Run in the SAME PowerShell session where you already ran Connect-MgGraph.
Something like: Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All" -UseDeviceAuthentication
works great for me.
Usage: pwsh -NoProfile .\Get-DisabledUsers-Licenses-GroupAware.ps1 -ExportCsv .\disabled_licenses.csv
#>

param(
    [string]$ExportCsv = ".\disabled_licenses.csv"
)

function Info { param($m) Write-Host $m -ForegroundColor Cyan }
function Warn { param($m) Write-Host $m -ForegroundColor Yellow }
function Err  { param($m) Write-Host $m -ForegroundColor Red }

# Require existing Graph context (reuse same session)
if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
    Err "No Graph context found in this session. Run Connect-MgGraph -Scopes <scopes> first in this window."
    return
}

Info "Building SKU maps (SkuId/AccountSkuId -> SkuPartNumber)..."
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
    Info ("Subscribed SKUs loaded: {0}" -f $skus.Count)
} catch {
    Warn "Could not enumerate subscribed SKUs: $($_.Exception.Message). Name resolution may be limited."
}

Info "Enumerating disabled users..."
$users = Get-MgUser -Filter "accountEnabled eq false" -Property "displayName,userPrincipalName,id" -All -ErrorAction Stop
Info ("Total disabled users found: {0}" -f $users.Count)

$results = @()
$counter = 0

foreach ($u in $users) {
    $counter++
    if ($counter % 200 -eq 0) { Info "Processed $counter users..." }

    $licenseNames = @()
    $source = ""

    # 1) Try licenseDetails (effective licenses)
    try {
        $ld = Get-MgUserLicenseDetail -UserId $u.Id -ErrorAction Stop
    } catch {
        $ld = @()
    }

    if ($ld -and $ld.Count -gt 0) {
        $licenseNames = $ld | ForEach-Object { $_.SkuPartNumber } | Where-Object { $_ } | Select-Object -Unique
        $source = "licenseDetails"
    } else {
        # 2) Fallback: check group-based licensing
        # Get groups the user is a member of (transitive membership)
        try {
            $memberOf = Get-MgUserMemberOf -UserId $u.Id -All -ErrorAction Stop
        } catch {
            $memberOf = @()
        }

        if ($memberOf -and $memberOf.Count -gt 0) {
            # For each group object, if it's a group, get group's assignedLicenses
            foreach ($m in $memberOf) {
                # memberOf returns directoryObject shapes; check objectType or @odata.type
                $isGroup = $false
                if ($m.AdditionalProperties.ContainsKey('@odata.type')) {
                    $odata = $m.AdditionalProperties['@odata.type']
                    if ($odata -like '*group*') { $isGroup = $true }
                }
                # fallback: check if object has 'displayName' and 'group' like properties
                if (-not $isGroup -and $m.PSObject.Properties.Match('DisplayName').Count -gt 0 -and $m.PSObject.Properties.Match('Id').Count -gt 0) {
                    # treat as group candidate
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

    if ($licenseNames.Count -gt 0) {
        $results += [PSCustomObject]@{
            DisplayName = $u.DisplayName
            UserPrincipalName = $u.UserPrincipalName
            LicenseNames = ,$licenseNames
            Source = $source
        }
    }
}

Info ("Total disabled users with discovered licenses: {0}" -f $results.Count)

if ($results.Count -eq 0) {
    Warn "No licenses discovered via licenseDetails or group assignedLicenses. If the original script still shows users, run it now and capture one UPN it reports; then re-run this script for that UPN specifically so we can compare."
    return
}

# Build columns License1..N
$max = ($results | ForEach-Object { $_.LicenseNames.Count } | Measure-Object -Maximum).Maximum
if (-not $max) { $max = 0 }

$output = foreach ($r in $results) {
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

# Print sample and export CSV
$output | Select-Object -First 20 | Format-Table -AutoSize

if ($ExportCsv) {
    try {
        $output | Export-Csv -Path $ExportCsv -NoTypeInformation -Force
        Info "`nExported results to $ExportCsv"
    } catch {
        Warn "Failed to export CSV: $($_.Exception.Message)"
    }
}

Info "`nDone."