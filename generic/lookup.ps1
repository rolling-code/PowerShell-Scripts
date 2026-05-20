$kev = (Get-Content kev.json | ConvertFrom-Json).vulnerabilities
$epss = Import-Csv epss.csv

$myCves = @(

    [PSCustomObject]@{
        Asset = "FooBAR - Linux Python setuptools"
        CVE   = "CVE-2022-40897"
    },

)



$result = foreach ($entry in $myCves) {

    $cve = $entry.CVE

    $kevHit = $kev | Where-Object { $_.cveID -eq $cve }
    $epssHit = $epss | Where-Object { $_.cve -eq $cve }

    [PSCustomObject]@{
        Asset = $entry.Asset
        CVE   = $cve
        KEV   = if ($kevHit) { "YES" } else { "NO" }
        EPSS  = if ($epssHit) { [math]::Round([double]$epssHit.epss, 5) } else { "N/A" }
		Risk = switch ($true) {
			($epssHit.epss -gt 0.02) { "MEDIUM" }
			($epssHit.epss -gt 0.005) { "LOW-MED" }
			default { "LOW" }
		}
    }
}

$result | Format-Table -AutoSize