
# Requires ActiveDirectory module
Import-Module ActiveDirectory

# Get all domain-joined computers
$computers = Get-ADComputer -Filter * -Property Name | Select-Object -ExpandProperty Name

# Output array
$results = @()

foreach ($computer in $computers) {
    Write-Host "Checking $computer..." -ForegroundColor Cyan
    try {
        $smbSettings = Get-WmiObject -Class Win32_Registry -ComputerName $computer -ErrorAction Stop

        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $computer)
        $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")

        $require = $key.GetValue("RequireSecuritySignature", "Not Set")
        $enable = $key.GetValue("EnableSecuritySignature", "Not Set")

        $results += [PSCustomObject]@{
            ComputerName = $computer
            RequireSMBSigning = $require
            EnableSMBSigning  = $enable
        }
    } catch {
        $results += [PSCustomObject]@{
            ComputerName = $computer
            RequireSMBSigning = "Error"
            EnableSMBSigning  = "Error"
        }
    }
}

# Export results to CSV
$results | Export-Csv -Path ".\SMB_Signing_Audit.csv" -NoTypeInformation
Write-Host "Audit complete. Results saved to SMB_Signing_Audit.csv" -ForegroundColor Green
