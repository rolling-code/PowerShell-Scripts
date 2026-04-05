param (
    [Parameter(Mandatory=$true)]
    [string]$CsvPath
)

# --- Output file with timestamp ---
$outputFile = "crt_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results = @()

Write-Host "========== START =========="
Write-Host "=> Input CSV: $CsvPath"
Write-Host "=> Output CSV: $outputFile"

# --- Validate CSV ---
if (-not (Test-Path $CsvPath)) {
    Write-Host "[ERROR] CSV file not found!"
    exit
}

# --- Load CSV ---
$rows = Import-Csv -Path $CsvPath
Write-Host "=> Rows loaded: $($rows.Count)"

# --- Port test ---
function Test-Port {
    param (
        [string]$Target,
        [int]$Port,
        [int]$TimeoutMs = 3000
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($Target, $Port, $null, $null)

        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $client.Close()
            return $false
        }

        $client.EndConnect($iar)
        $client.Close()
        return $true
    }
    catch {
        return $false
    }
}

# --- Get HTTP title ---
function Get-HttpTitle {
    param (
        [string]$Url
    )

    try {
        Write-Host "   [DEBUG] Fetching $Url"

        $resp = Invoke-WebRequest -Uri $Url -TimeoutSec 10 -ErrorAction Stop

        if ($resp.Content -match "<title>(.*?)</title>") {
            return $matches[1].Trim()
        }
        else {
            return ""
        }
    }
    catch {
        return ""
    }
}

# --- Query crt.sh ---
function Invoke-CrtQuery {
    param ($Domain)

    $url = "https://crt.sh/?q=$Domain&output=json"

    for ($i = 1; $i -le 3; $i++) {
        Write-Host "=> Attempt $i/3 : $url"

        try {
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 30

            if ($response.StatusCode -eq 200) {
                $jsonText = $response.Content -replace "}\s*{", "},{"
                $jsonText = "[$jsonText]"
                return $jsonText | ConvertFrom-Json
            }
        }
        catch {
            Write-Host "[ERROR] $($_.Exception.Message)"
        }

        Start-Sleep -Seconds 2
    }

    return $null
}

# --- Extract domains ---
function Extract-Domains {
    param ($JsonData)

    $domains = New-Object System.Collections.Generic.HashSet[string]

    foreach ($entry in $JsonData) {
        if ($entry.name_value) {
            $names = $entry.name_value -split "`n"

            foreach ($n in $names) {
                $clean = $n.Trim().ToLower()

                if ($clean -match '^[a-zA-Z0-9\.\-\*]+\.[a-zA-Z]{2,}$') {
                    $clean = $clean -replace '^\*\.', ''
                    $domains.Add($clean) | Out-Null
                }
            }
        }
    }

    return $domains
}

# --- MAIN LOOP ---
$index = 0

foreach ($row in $rows) {

    $index++
    Write-Host "`n=============================="
    Write-Host "=> Processing row #$index"

    if (-not $row.'Asset Name') {
        Write-Host "[WARNING] No Asset Name column, skipping"
        continue
    }

    $domain = $row.'Asset Name'.Trim().ToLower()
    Write-Host "=> Domain: $domain"

    # --- Query crt.sh ---
    $json = Invoke-CrtQuery -Domain $domain

    if (-not $json) {
        Write-Host "[WARNING] No crt.sh data"
        continue
    }

    $foundDomains = Extract-Domains -JsonData $json
    $newDomains = $foundDomains | Where-Object { $_ -ne $domain }

    foreach ($nd in $newDomains) {
        Write-Host "=> NEW DOMAIN: $nd"
    }

    $allDomains = @($domain) + $newDomains

    foreach ($d in $allDomains) {

        Write-Host "`n=> Checking $d"

        # --- Ports ---
        $p80   = Test-Port -Target $d -Port 80
        $p443  = Test-Port -Target $d -Port 443
        $p22   = Test-Port -Target $d -Port 22
        $p3389 = Test-Port -Target $d -Port 3389

        $r80   = if ($p80) { "OK" } else { "NA" }
        $r443  = if ($p443) { "OK" } else { "NA" }
        $r22   = if ($p22) { "OK" } else { "NA" }
        $r3389 = if ($p3389) { "OK" } else { "NA" }

        # --- Titles ---
        $title80  = if ($p80)  { Get-HttpTitle "http://$d" }  else { "" }
        $title443 = if ($p443) { Get-HttpTitle "https://$d" } else { "" }

        Write-Host "RESULT => $d : 80 $r80 | 443 $r443 | 22 $r22 | 3389 $r3389"

        if ($title80)  { Write-Host "   Title(80): $title80" }
        if ($title443) { Write-Host "   Title(443): $title443" }

        # --- Save ---
        $results += [PSCustomObject]@{
            SourceDomain     = $domain
            DiscoveredDomain = $d
            IsNew            = ($d -ne $domain)
            Port80           = $r80
            Port443          = $r443
            Port22           = $r22
            Port3389         = $r3389
            Title80          = $title80
            Title443         = $title443
        }
    }
}

# --- Deduplicate ---
$results = $results | Sort-Object SourceDomain,DiscoveredDomain -Unique

# --- Export ---
Write-Host "`n=> Saving results..."

$results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

Write-Host "=> Done. File: $outputFile"
Write-Host "========== END =========="