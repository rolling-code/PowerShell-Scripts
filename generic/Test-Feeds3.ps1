<#
.SYNOPSIS
  Download and test connectivity for URLhaus, OpenPhish & IPSum feeds.
.PARAMETER Quick
  If specified, only the first 25 lines of each feed are processed.
#>
param(
    [switch]$Quick
)

# ==== CONFIGURATION & GLOBAL COUNTERS ====
$tempDir = "C:\temp"
if (-not (Test-Path $tempDir)) {
    New-Item -Path $tempDir -ItemType Directory | Out-Null
}

# Grand totals
$script:TotalEntries   = 0
$script:ProcessedCount = 0

# Per-feed counters – initialize everything to zero up front
$script:URLhausTotal   = 0; $script:URLhausSuccess   = 0; $script:URLhausFail   = 0
$script:OpenPhishTotal = 0; $script:OpenPhishSuccess = 0; $script:OpenPhishFail = 0
$script:IPSumTotal     = 0; $script:IPSumSuccess     = 0; $script:IPSumFail     = 0



# Per-feed counters - same as above pick one
$feeds = 'URLhaus','OpenPhish','IPSum'
foreach ($f in $feeds) {
    Set-Variable -Name "${f}Total"   -Scope Script -Value 0
    Set-Variable -Name "${f}Success" -Scope Script -Value 0
    Set-Variable -Name "${f}Fail"    -Scope Script -Value 0
}
 
# Deduplication table
$Tested = @{}

# ==== FAST TCP PORT TESTER ====
function Test-Port {
    [CmdletBinding()]
    param(
        [Alias('Host')]
        [Parameter(Mandatory, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory, Position=1)]
        [int]$Port,

        [Parameter()]
        [int]$TimeoutMs = 300 #A 1 000 ms (1 s) or even 2 000 ms timeout will cover typical cross-Pacific latencies without slowing down local tests too much.
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.EndConnect($async)
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

# ==== PROCESS URL ====
function Process-Url {
    param(
        [string]$Url,
        [string]$FeedName
    )
    try {
        $u = [Uri]$Url
    } catch {
        Write-Host "Invalid URL skipped: $Url" -ForegroundColor Yellow
        return
    }

    $port = if ($u.IsDefaultPort) {
        if ($u.Scheme -eq 'https') { 443 } else { 80 }
    } else {
        $u.Port
    }

    $key = "$($u.Host):$port"
    if ($Tested.ContainsKey($key)) {
        Write-Host "Skipping already tested $key" -ForegroundColor DarkGray
        return
    }
    $Tested[$key] = $true

    # Increment counters
    $script:ProcessedCount++
    Set-Variable -Name "${FeedName}Total" -Scope Script `
        -Value ((Get-Variable -Name "${FeedName}Total" -Scope Script).Value + 1)

    if (Test-Port $u.Host $port) {
        Set-Variable -Name "${FeedName}Success" -Scope Script `
            -Value ((Get-Variable -Name "${FeedName}Success" -Scope Script).Value + 1)

        Write-Host ("[{0}/{1}] {2}:{3} → Success ({4})" `
            -f $script:ProcessedCount, $script:TotalEntries, $u.Host, $port, $Url) `
            -ForegroundColor Red
    } else {
        Set-Variable -Name "${FeedName}Fail" -Scope Script `
            -Value ((Get-Variable -Name "${FeedName}Fail" -Scope Script).Value + 1)

        Write-Host ("[{0}/{1}] {2}:{3} → Failed ({4})" `
            -f $script:ProcessedCount, $script:TotalEntries, $u.Host, $port, $Url) `
            -ForegroundColor Green
    }
}

function Process-Ip {
    param(
        [string]$Ip,
        [string]$FeedName
    )

    $succeeded = $false
    foreach ($p in 80,443) {
        # fix the interpolation here
        $key = "$($Ip):$($p)"
        if ($Tested.ContainsKey($key)) {
            Write-Host "Skipping already tested $key" -ForegroundColor DarkGray
            continue
        }
        $Tested[$key] = $true

        $script:ProcessedCount++
        Set-Variable -Name "${FeedName}Total" -Scope Script `
            -Value ((Get-Variable -Name "${FeedName}Total" -Scope Script).Value + 1)

        if (Test-Port $Ip $p) {
            Set-Variable -Name "${FeedName}Success" -Scope Script `
                -Value ((Get-Variable -Name "${FeedName}Success" -Scope Script).Value + 1)

            Write-Host ("[{0}/{1}] {2}:{3} → Success" `
                -f $script:ProcessedCount, $script:TotalEntries, $Ip, $p) `
                -ForegroundColor Red
            $succeeded = $true
            break
        }
    }

    if (-not $succeeded) {
        Set-Variable -Name "${FeedName}Fail" -Scope Script `
            -Value ((Get-Variable -Name "${FeedName}Fail" -Scope Script).Value + 1)

        Write-Host ("[{0}/{1}] {2} → Failed on ports 80 & 443" `
            -f $script:ProcessedCount, $script:TotalEntries, $Ip) `
            -ForegroundColor Green
    }
}

# ==== STEP 1: URLhaus Feed ====
$zipUrl     = "https://urlhaus.abuse.ch/downloads/csv/"
$zipFile    = Join-Path $tempDir "URLhaus.zip"
$extractDir = Join-Path $tempDir "URLhaus"

Write-Host "`nDownloading URLhaus feed from $zipUrl" -ForegroundColor Cyan
Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing

Write-Host "Extracting to $extractDir" -ForegroundColor Cyan
Expand-Archive -LiteralPath $zipFile -DestinationPath $extractDir -Force

$csvFile = Get-ChildItem -Path $extractDir -Filter '*.txt' -File | Select-Object -First 1
if ($csvFile) {
    $allUrlLines = Get-Content $csvFile.FullName |
        Where-Object { -not $_.StartsWith('#') -and -not [string]::IsNullOrWhiteSpace($_) }
    if ($Quick) {
        $urlLines = $allUrlLines[0..([Math]::Min(24, $allUrlLines.Count - 1))]
    } else {
        $urlLines = $allUrlLines
    }
    $script:TotalEntries += $urlLines.Count

    Write-Host "`nProcessing URLhaus URLs" -ForegroundColor Cyan
    foreach ($line in $urlLines) {
        if ($line -match '^".*",".*",".*",".*",".*",".*",".*",".*",".*"$') {
            $fields = $line.Trim('"') -split '","'
            Process-Url $fields[2] 'URLhaus'
        } else {
            Write-Host "Skipping malformed line: $line" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "No CSV .txt file found in $extractDir" -ForegroundColor Yellow
}

Remove-Item -Path $zipFile, $extractDir -Recurse -Force

# ==== STEP 2: OpenPhish Feed ====
$feed2Url  = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
$feed2File = Join-Path $tempDir "openphish.txt"

Write-Host "`nDownloading OpenPhish feed" -ForegroundColor Cyan
Invoke-WebRequest -Uri $feed2Url -OutFile $feed2File -UseBasicParsing

$opfAll    = Get-Content $feed2File
$opfLines  = $opfAll | Where-Object { $_ -match '^https?://' }
if ($Quick) {
    $opfLines = $opfLines[0..([Math]::Min(24, $opfLines.Count - 1))]
}
$script:TotalEntries += $opfLines.Count

Write-Host "`nProcessing OpenPhish URLs" -ForegroundColor Cyan
foreach ($u in $opfLines) {
    Process-Url $u 'OpenPhish'
}

Remove-Item -Path $feed2File -Force

# ==== STEP 3: IPSum IP Feed ====
$feed3Url  = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
$feed3File = Join-Path $tempDir "ipsum.txt"

Write-Host "`nDownloading IPSum feed" -ForegroundColor Cyan
Invoke-WebRequest -Uri $feed3Url -OutFile $feed3File -UseBasicParsing

$ipsumAll = Get-Content $feed3File
$ipsumLines = $ipsumAll | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' }
if ($Quick) {
    $ipsumLines = $ipsumLines[0..([Math]::Min(24, $ipsumLines.Count - 1))]
}

# $script:TotalEntries += $ipsumLines.Count
# count each IP twice (ports 80 & 443)
$script:TotalEntries += ($ipsumLines.Count * 2)

Write-Host "`nProcessing IPSum IPs" -ForegroundColor Cyan
foreach ($line in $ipsumLines) {
    $ip = ($line -split '\s+')[0]
    Process-Ip $ip 'IPSum'
}

Remove-Item -Path $feed3File -Force

# ==== FINAL SUMMARY ====
Write-Host "`n# GRAND TOTALS" -ForegroundColor Cyan
$overallSuccess = $URLhausSuccess + $OpenPhishSuccess + $IPSumSuccess
$overallFail    = $URLhausFail    + $OpenPhishFail    + $IPSumFail

Write-Host "# Entries processed:       $script:TotalEntries"
Write-Host "# Overall Success:        $overallSuccess"
Write-Host "# Overall Failures:       $overallFail"

Write-Host "`n# Per-Feed Breakdown" -ForegroundColor Cyan
foreach ($f in $feeds) {
    $t = (Get-Variable -Name "${f}Total"   -Scope Script).Value
    $s = (Get-Variable -Name "${f}Success" -Scope Script).Value
    $e = (Get-Variable -Name "${f}Fail"    -Scope Script).Value
    Write-Host ("# {0,-10} → Total: {1,-4}  Success: {2,-4}  Fail: {3,-4}" `
        -f $f, $t, $s, $e)
}
