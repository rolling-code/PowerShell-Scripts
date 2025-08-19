<#
.SYNOPSIS
  Resolve domains to IPv4, then do reverse DNS lookups, marking offline hosts.

.PARAMETER InputPath
  Path to file containing domains (one per line; extra text allowed).

.PARAMETER OutputPath
  Path to file where results will be written.
#>
param(
    [Parameter(Mandatory)]
    [string]$InputPath  = 'all_domains.txt',

    [Parameter(Mandatory)]
    [string]$OutputPath = 'ips.txt'
)

# 0. Ensure input exists
if (-not (Test-Path $InputPath)) {
    Write-Error "Input file '$InputPath' not found."
    exit 1
}

# 1. Read & sanitize domains
Write-Host "Step 1: Loading domains…"
$domains = Get-Content -LiteralPath $InputPath |
    ForEach-Object {
        $token = ($_ -split '\s+')[0].Trim()
        if ($token -and $token -match '^[a-zA-Z0-9\.-]+$') {
            $token
        }
        else {
            Write-Warning "  Skipping invalid line: '$_'"
            $null
        }
    }

if ($domains.Count -eq 0) {
    Write-Error "No valid domains to process."
    exit 1
}

Write-Host "  → $($domains.Count) domains queued.`n"

# 2. Resolve & Reverse in one pass, record “offline” when appropriate
Write-Host "Step 2: Resolving and reverse‐looking up…"
$results = New-Object System.Collections.Generic.List[PSObject]

foreach ($domain in $domains) {
    Write-Host "  Processing $domain…"
    try {
        $ips = Resolve-DnsName -Name $domain -Type A -ErrorAction Stop |
               Select-Object -ExpandProperty IPAddress -Unique

        if ($ips) {
            foreach ($ip in $ips) {
                Write-Host "    → $domain -> $ip"
                try {
                    $ptr = [System.Net.Dns]::GetHostEntry($ip).HostName
                    Write-Host "       PTR: $ptr"
                }
                catch {
                    Write-Warning "       PTR lookup failed for $ip"
                    $ptr = ''
                }

                $results.Add(
                    [PSCustomObject]@{
                        Domain      = $domain
                        IP          = $ip
                        ReverseHost = $ptr
                    }
                )
            }
        }
        else {
            Write-Warning "    No A records for $domain"
            $results.Add(
                [PSCustomObject]@{
                    Domain      = $domain
                    IP          = 'offline'
                    ReverseHost = ''
                }
            )
        }
    }
    catch {
        $msg = $_.Exception.Message
        Write-Warning "    Resolve failed for $($domain): $msg"
        $results.Add(
            [PSCustomObject]@{
                Domain      = $domain
                IP          = 'offline'
                ReverseHost = ''
            }
        )
    }
}

Write-Host "`n  Collected $($results.Count) entries.`n"

# 3. Emit output
Write-Host "Step 3: Writing results to '$OutputPath'…"
$results |
    ForEach-Object {
        if ($_.IP -eq 'offline') {
            # smart offline marker
            "$($_.Domain)->offline"
        }
        else {
            # normal domain->ip->reverse
            "$($_.Domain)->$($_.IP)->$($_.ReverseHost)"
        }
    } |
    Set-Content -LiteralPath $OutputPath

Write-Host "Done. Output saved."