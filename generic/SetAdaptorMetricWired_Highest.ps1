<#
.SYNOPSIS
Set interface metrics for physical adapters only.
- Disconnected physical adapters => metric 100
- Connected physical adapters => metric 10 (except when both wired+wifi are Up: wired=10, wifi=50)
- Use -Trial to preview planned changes without applying them
#>

param(
    [switch]$Trial
)

# Patterns (adjust if your adapter names differ)
$wiredPatterns = @('Ethernet*','Local Area Connection*')
$wifiPatterns  = @('Wi-Fi*','Wi‑Fi*','Wireless Network Connection*','Wireless*')

function MatchesPattern($alias, $patterns) {
    foreach ($p in $patterns) { if ($alias -like $p) { return $true } }
    return $false
}

# Get only physical adapters
$allAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue

if (-not $allAdapters) {
    Write-Host "No physical adapters found. Exiting."
    return
}

# Detect Up wired and Up wifi presence (physical adapters only)
$upAdapters = $allAdapters | Where-Object { $_.Status -eq 'Up' }
$upWired = $upAdapters | Where-Object { MatchesPattern $_.InterfaceAlias $wiredPatterns }
$upWifi  = $upAdapters | Where-Object { MatchesPattern $_.InterfaceAlias $wifiPatterns }

$planned = @()

foreach ($a in $allAdapters) {
    $alias = $a.InterfaceAlias.Trim()
    if ([string]::IsNullOrWhiteSpace($alias)) { continue }
    $ipif = Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    $current = ($ipif.InterfaceMetric -as [int])

    if ($a.Status -eq 'Disconnected') {
        $typeVal = if (MatchesPattern $alias $wiredPatterns) { 'Wired' } elseif (MatchesPattern $alias $wifiPatterns) { 'Wireless' } else { 'Other' }
        $planned += [pscustomobject]@{
            InterfaceAlias = $alias
            Status         = $a.Status
            Type           = $typeVal
            CurrentMetric  = $current
            PlannedMetric  = 100
            Reason         = 'Disconnected'
        }
        continue
    }

    if ($a.Status -eq 'Up') {
        if (($upWired.Count -gt 0) -and ($upWifi.Count -gt 0)) {
            # Both present: prefer wired
            if (MatchesPattern $alias $wiredPatterns) {
                $pm = 10
                $reason = 'Wired up (prefer)'
            } elseif (MatchesPattern $alias $wifiPatterns) {
                $pm = 50
                $reason = 'Wi‑Fi up (deprioritized because wired also up)'
            } else {
                $pm = 10
                $reason = 'Other Up'
            }
        }
        else {
            # Not both present: any Up physical adapter gets 10
            $pm = 10
            $reason = 'Only adapter type Up => prioritized'
        }

        $typeVal = if (MatchesPattern $alias $wiredPatterns) { 'Wired' } elseif (MatchesPattern $alias $wifiPatterns) { 'Wireless' } else { 'Other' }

        $planned += [pscustomobject]@{
            InterfaceAlias = $alias
            Status         = $a.Status
            Type           = $typeVal
            CurrentMetric  = $current
            PlannedMetric  = $pm
            Reason         = $reason
        }
    }
}

if ($planned.Count -eq 0) {
    Write-Host "No planned changes determined for physical adapters."
    return
}

Write-Host "Planned changes:`n"
$planned | Sort-Object Type, InterfaceAlias | Format-Table InterfaceAlias, Status, Type, CurrentMetric, PlannedMetric, Reason -AutoSize

if ($Trial) {
    Write-Host "`nTrial mode enabled: no changes will be applied."
    return
}

# Apply only when different
foreach ($p in $planned) {
    if ($p.CurrentMetric -eq $p.PlannedMetric) {
        Write-Host "No change required for '$($p.InterfaceAlias)' (metric already $($p.CurrentMetric))."
        continue
    }
    try {
        Write-Host "Setting metric $($p.PlannedMetric) on interface '$($p.InterfaceAlias)' (was $($p.CurrentMetric))."
        Set-NetIPInterface -InterfaceAlias $p.InterfaceAlias -InterfaceMetric $p.PlannedMetric -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to set metric on '$($p.InterfaceAlias)': $($_.Exception.Message)"
    }
}

Write-Host "Done."