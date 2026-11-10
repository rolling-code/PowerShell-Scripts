<#
.SYNOPSIS
  Downloads OpenPhish and IPSum feeds and performs quick connectivity checks.

.DESCRIPTION
  Tests whether sampled OpenPhish URL hosts accept TCP connections on their
  advertised ports and whether sampled IPSum IP addresses accept TCP
  connections on ports 80 or 443.

  This is a reachability comparison tool. A failed TCP connection does not by
  itself prove that DNS, NRPT, a firewall, or a security product blocked the
  destination. Review DNS resolution and connection errors separately when
  validating a filtering control.

.PARAMETER Quick
  Processes the first 25 entries from each feed.

.PARAMETER TimeoutMs
  Specifies the TCP connection timeout for each port test. The default is
  1500 milliseconds.

.NOTES
  Version: 2.0.1
  URLhaus was removed because the former unauthenticated CSV download endpoint
  now returns HTTP 410 Gone and URLhaus bulk exports require authenticated API
  access.
#>

[CmdletBinding()]
param(
    [switch]$Quick,

    [ValidateRange(100, 30000)]
    [int]$TimeoutMs = 1500
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$TempDir = Join-Path $env:TEMP 'Test-Feeds3'
New-Item -Path $TempDir -ItemType Directory -Force | Out-Null

$script:ScheduledEntries = 0
$script:ProcessedCount = 0
$script:SkippedDuplicates = 0

$Feeds = @('OpenPhish', 'IPSum')
foreach ($Feed in $Feeds) {
    Set-Variable -Name "${Feed}Total" -Scope Script -Value 0
    Set-Variable -Name "${Feed}Reachable" -Scope Script -Value 0
    Set-Variable -Name "${Feed}NotReachable" -Scope Script -Value 0
}

$Tested = @{}

function Test-Port {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory, Position = 1)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [Parameter(Mandatory)]
        [ValidateRange(100, 30000)]
        [int]$ConnectionTimeoutMs
    )

    $Client = [System.Net.Sockets.TcpClient]::new()
    try {
        $Async = $Client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $Async.AsyncWaitHandle.WaitOne($ConnectionTimeoutMs)) {
            return $false
        }

        $Client.EndConnect($Async)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $Client.Dispose()
    }
}

function Add-FeedCounter {
    param(
        [Parameter(Mandatory)]
        [string]$FeedName,

        [Parameter(Mandatory)]
        [ValidateSet('Total', 'Reachable', 'NotReachable')]
        [string]$Counter
    )

    $Name = "${FeedName}${Counter}"
    $Value = (Get-Variable -Name $Name -Scope Script).Value
    Set-Variable -Name $Name -Scope Script -Value ($Value + 1)
}

function Process-Url {
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$FeedName
    )

    try {
        $Uri = [Uri]$Url
    }
    catch {
        Write-Host "Invalid URL skipped: $Url" -ForegroundColor Yellow
        return
    }

    if ($Uri.Scheme -notin @('http', 'https')) {
        Write-Host "Unsupported URL scheme skipped: $Url" -ForegroundColor Yellow
        return
    }

    $Port = if ($Uri.IsDefaultPort) {
        if ($Uri.Scheme -eq 'https') { 443 } else { 80 }
    }
    else {
        $Uri.Port
    }

    $Key = "$($Uri.Host.ToLowerInvariant()):$Port"
    if ($Tested.ContainsKey($Key)) {
        $script:SkippedDuplicates++
        Write-Host "Skipping already tested $Key" -ForegroundColor DarkGray
        return
    }

    $Tested[$Key] = $true
    $script:ProcessedCount++
    Add-FeedCounter -FeedName $FeedName -Counter Total

    if (Test-Port -ComputerName $Uri.Host -Port $Port -ConnectionTimeoutMs $TimeoutMs) {
        Add-FeedCounter -FeedName $FeedName -Counter Reachable
        Write-Host ("[{0}/{1}] {2}:{3} -> Reachable ({4})" -f $script:ProcessedCount, $script:ScheduledEntries, $Uri.Host, $Port, $Url) -ForegroundColor Red
    }
    else {
        Add-FeedCounter -FeedName $FeedName -Counter NotReachable
        Write-Host ("[{0}/{1}] {2}:{3} -> Not reachable ({4})" -f $script:ProcessedCount, $script:ScheduledEntries, $Uri.Host, $Port, $Url) -ForegroundColor Green
    }
}

function Process-Ip {
    param(
        [Parameter(Mandatory)]
        [string]$Ip,

        [Parameter(Mandatory)]
        [string]$FeedName
    )

    $Key = "IP:$Ip"
    if ($Tested.ContainsKey($Key)) {
        $script:SkippedDuplicates++
        Write-Host "Skipping already tested IP $Ip" -ForegroundColor DarkGray
        return
    }

    $Tested[$Key] = $true
    $script:ProcessedCount++
    Add-FeedCounter -FeedName $FeedName -Counter Total

    $ReachablePort = $null
    foreach ($Port in @(80, 443)) {
        if (Test-Port -ComputerName $Ip -Port $Port -ConnectionTimeoutMs $TimeoutMs) {
            $ReachablePort = $Port
            break
        }
    }

    if ($null -ne $ReachablePort) {
        Add-FeedCounter -FeedName $FeedName -Counter Reachable
        Write-Host ("[{0}/{1}] {2}:{3} -> Reachable" -f $script:ProcessedCount, $script:ScheduledEntries, $Ip, $ReachablePort) -ForegroundColor Red
    }
    else {
        Add-FeedCounter -FeedName $FeedName -Counter NotReachable
        Write-Host ("[{0}/{1}] {2} -> Not reachable on ports 80 and 443" -f $script:ProcessedCount, $script:ScheduledEntries, $Ip) -ForegroundColor Green
    }
}

$OpenPhishFile = Join-Path $TempDir 'openphish.txt'
$IPSumFile = Join-Path $TempDir 'ipsum.txt'

try {
    $OpenPhishUrl = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'
    Write-Host "`nDownloading OpenPhish feed" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $OpenPhishUrl -OutFile $OpenPhishFile -UseBasicParsing

    $OpenPhishLines = @(
        Get-Content -LiteralPath $OpenPhishFile |
            Where-Object { $_ -match '^https?://' }
    )

    if ($Quick -and $OpenPhishLines.Count -gt 25) {
        $OpenPhishLines = @($OpenPhishLines | Select-Object -First 25)
    }

    $IPSumUrl = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
    Write-Host "`nDownloading IPSum feed" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $IPSumUrl -OutFile $IPSumFile -UseBasicParsing

    $IPSumLines = @(
        Get-Content -LiteralPath $IPSumFile |
            Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' }
    )

    if ($Quick -and $IPSumLines.Count -gt 25) {
        $IPSumLines = @($IPSumLines | Select-Object -First 25)
    }

    $script:ScheduledEntries = $OpenPhishLines.Count + $IPSumLines.Count

    Write-Host "`nProcessing OpenPhish URLs" -ForegroundColor Cyan
    foreach ($Url in $OpenPhishLines) {
        Process-Url -Url $Url -FeedName 'OpenPhish'
    }

    Write-Host "`nProcessing IPSum IPs" -ForegroundColor Cyan
    foreach ($Line in $IPSumLines) {
        $Ip = ($Line -split '\s+')[0]
        Process-Ip -Ip $Ip -FeedName 'IPSum'
    }
}
finally {
    Remove-Item -LiteralPath $OpenPhishFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $IPSumFile -Force -ErrorAction SilentlyContinue
}

$OverallReachable = $OpenPhishReachable + $IPSumReachable
$OverallNotReachable = $OpenPhishNotReachable + $IPSumNotReachable
$OverallClassified = $OverallReachable + $OverallNotReachable

Write-Host "`n# GRAND TOTALS" -ForegroundColor Cyan
Write-Host "# Entries scheduled:      $script:ScheduledEntries"
Write-Host "# Unique entries tested:  $script:ProcessedCount"
Write-Host "# Duplicates skipped:      $script:SkippedDuplicates"
Write-Host "# Reachable results:       $OverallReachable"
Write-Host "# Not reachable results:   $OverallNotReachable"
Write-Host "# Classified results:      $OverallClassified"

Write-Host "`n# Per-Feed Breakdown" -ForegroundColor Cyan
foreach ($Feed in $Feeds) {
    $Total = (Get-Variable -Name "${Feed}Total" -Scope Script).Value
    $Reachable = (Get-Variable -Name "${Feed}Reachable" -Scope Script).Value
    $NotReachable = (Get-Variable -Name "${Feed}NotReachable" -Scope Script).Value
    Write-Host ("# {0,-10} -> Total: {1,-4} Reachable: {2,-4} Not reachable: {3,-4}" -f $Feed, $Total, $Reachable, $NotReachable)
}

if ($OverallClassified -ne $script:ProcessedCount) {
    Write-Host "`n[WARN] Summary mismatch detected: tested=$script:ProcessedCount; classified=$OverallClassified." -ForegroundColor Yellow
    exit 2
}

Write-Host "`n[NOTE] A TCP failure is not proof of DNS or security-control blocking." -ForegroundColor Yellow
Write-Host "[NOTE] IPSum tests raw IP addresses, so DNS filtering cannot affect those results." -ForegroundColor Yellow
exit 0
