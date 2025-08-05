
# Requires ActiveDirectory module
Import-Module ActiveDirectory

# Get all domain-joined computers
$computers = Get-ADComputer -Filter * -Property Name | Select-Object -ExpandProperty Name

# Output array
$results = @()

foreach ($computer in $computers) {
    Write-Host "Checking $computer..." -ForegroundColor Cyan
    try {
        $smbSettings = Invoke-Command -ComputerName $computer -ScriptBlock {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
            $require = $key.GetValue("RequireSecuritySignature", "Not Set")
            $enable = $key.GetValue("EnableSecuritySignature", "Not Set")
            [PSCustomObject]@{
                RequireSMBSigning = $require
                EnableSMBSigning  = $enable
            }
        }
        $results += [PSCustomObject]@{
            ComputerName = $computer
            RequireSMBSigning = $smbSettings.RequireSMBSigning
            EnableSMBSigning  = $smbSettings.EnableSMBSigning
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
