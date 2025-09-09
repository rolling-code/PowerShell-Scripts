<#
.SYNOPSIS
  Download and test connectivity for URLhaus, OpenPhish & IPSum feeds.
.PARAMETER Quick
  If specified, only the first 25 lines of each feed are processed.
#>
param(
    [switch]$Quick
)

# ==== CONFIGURATION ====
$tempDir = "C:\temp"
if (-not (Test-Path $tempDir)) {
    New-Item -Path $tempDir -ItemType Directory | Out-Null
}

$script:TotalTests   = 0
$script:SuccessCount = 0
$script:FailCount    = 0

# Hashtable to remember tested Host:Port combos
$Tested = @{}

function Process-Url {
    param($url)
    try { $u = [Uri]$url } catch {
        Write-Host "Invalid URL skipped: $url" -ForegroundColor Yellow
        return
    }
    $port = if ($u.IsDefaultPort) { if ($u.Scheme -eq 'https') {443} else {80} } else { $u.Port }
    $key = "$($u.Host):$port"
    if ($Tested.ContainsKey($key)) {
        Write-Host "Skipping already tested $key" -ForegroundColor DarkGray
        return
    }
    $Tested[$key] = $true

    $target = $u.Host
    if (-not [IPAddress]::TryParse($target, [ref]$null)) {
        $dnsServer = (Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -First 1).ServerAddresses[0]
        if ($dnsServer) {
            $res = Resolve-DnsName -Name $target -Server $dnsServer -ErrorAction SilentlyContinue |
                   Where-Object IPAddress | Select-Object -First 1
            if ($res) {
                Write-Host "Resolved $target to $($res.IPAddress) via DNS $dnsServer" -ForegroundColor Magenta
                $target = $res.IPAddress
            } else {
                Write-Host "DNS resolution failed for $target" -ForegroundColor Yellow
            }
        }
    }

    $script:TotalTests++
    if (Test-NetConnection -ComputerName $target -Port $port -InformationLevel Quiet) {
        Write-Host "$($u.Host):$port → Success ($url)" -ForegroundColor Red
        $script:SuccessCount++
    } else {
        Write-Host "$($u.Host):$port → Failed ($url)" -ForegroundColor Green
        $script:FailCount++
    }
}

function Process-Ip {
    param($ip)

    $succeeded = $false
    foreach ($p in 80, 443) {
        # Sub-expressions ensure the colon isn’t parsed as part of a variable name
        $key = "$($ip):$($p)"
        if ($Tested.ContainsKey($key)) {
            Write-Host "Skipping already tested $key" -ForegroundColor DarkGray
            continue
        }
        $Tested[$key] = $true

        $script:TotalTests++
        if (Test-NetConnection -ComputerName $ip -Port $p -InformationLevel Quiet) {
            Write-Host "$key → Success" -ForegroundColor Red
            $script:SuccessCount++
            $succeeded = $true
            break
        }
    }

    if (-not $succeeded) {
        Write-Host "$($ip) → Failed on ports 80 & 443" -ForegroundColor Green
        $script:FailCount++
    }
}

# ==== STEP 1: URLhaus CSV Feed ====
$zipUrl     = "https://urlhaus.abuse.ch/downloads/csv/"
$zipFile    = Join-Path $tempDir "URLhaus.zip"
$extractDir = Join-Path $tempDir "URLhaus"

Write-Host "`nDownloading URLhaus feed from $zipUrl" -ForegroundColor Cyan
Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing
Write-Host "Extracting to $extractDir" -ForegroundColor Cyan
Expand-Archive -LiteralPath $zipFile -DestinationPath $extractDir -Force

$csvFile = Get-ChildItem -Path $extractDir -Filter '*.txt' -File | Select-Object -First 1
if ($csvFile) {
    $lines = Get-Content $csvFile.FullName
    if ($Quick) {
        $lines = $lines[0..([Math]::Min(24, $lines.Count - 1))]
    }

    $last = ($lines | Where-Object { $_ -match '^#\s*Last updated:' })[0]
    Write-Host "`nurlhaus.abuse.ch" -ForegroundColor Cyan
    if ($last) {
        $clean = $last -replace '^#\s*', ''
        Write-Host $clean -ForegroundColor Cyan
    }

    foreach ($line in $lines) {
        if ($line.StartsWith('#') -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^".*",".*",".*",".*",".*",".*",".*",".*",".*"$') {
            $fields = $line.Trim('"') -split '","'
            Process-Url $fields[2]
        } else {
            Write-Host "Skipping malformed line: $line" -ForegroundColor Yellow
        }
    }
	$lines = Get-Content $csvFile.FullName
	Write-Host "URLhaus lines read: $($lines.Count)"
	if ($Quick) { $lines = $lines[0..([Math]::Min(24, $lines.Count-1))] }
} else {
    Write-Host "No CSV .txt file found in $extractDir" -ForegroundColor Yellow
}

Remove-Item -Path $zipFile, $extractDir -Recurse -Force

# ==== STEP 2: OpenPhish Feed ====
$feed2Url  = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
$feed2File = Join-Path $tempDir "openphish.txt"

Write-Host "`nDownloading OpenPhish feed" -ForegroundColor Cyan
Invoke-WebRequest -Uri $feed2Url -OutFile $feed2File -UseBasicParsing

$opfLines = Get-Content $feed2File
if ($Quick) {
    $opfLines = $opfLines[0..([Math]::Min(24, $opfLines.Count - 1))]
}

Write-Host "`nraw.githubusercontent.com/openphish/public_feed" -ForegroundColor Cyan
foreach ($u in $opfLines) {
    if ($u -match '^https?://') {
        Process-Url $u
    }
}
$opfLines = Get-Content $feed2File
Write-Host "OpenPhish lines read: $($opfLines.Count)"
Remove-Item -Path $feed2File -Force

# ==== STEP 3: IPSum IP Feed ====
$feed3Url  = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
$feed3File = Join-Path $tempDir "ipsum.txt"

Write-Host "`nDownloading IPSum feed" -ForegroundColor Cyan
Invoke-WebRequest -Uri $feed3Url -OutFile $feed3File -UseBasicParsing

$ipsumLines = Get-Content $feed3File
if ($Quick) {
    $ipsumLines = $ipsumLines[0..([Math]::Min(24, $ipsumLines.Count - 1))]
}

#Write-Host "`n# IPsum Threat Intelligence Feed" -ForegroundColor Cyan
#Write-Host "# (https://github.com/stamparm/ipsum)" -ForegroundColor Cyan
$ipsumLines | Select-Object -First 4 | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }

foreach ($line in $ipsumLines) {
    if (-not $line.StartsWith('#') -and $line -match '\d+\.\d+\.\d+\.\d+') {
        $ip = ($line -split '\s+')[0]
        Process-Ip $ip
    }
}
$ipsumLines = Get-Content $feed3File
Write-Host "IPSum lines read: $($opfLines.Count)"
Remove-Item -Path $feed3File -Force

# ==== FINAL SUMMARY ====  
Write-Host "`n# IPs/Domains: $script:TotalTests"
Write-Host "# Successful connections: $script:SuccessCount"
Write-Host "# Unsuccessful connections: $script:FailCount"