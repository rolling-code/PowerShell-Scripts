# Pull all servers from AD
$servers = Get-ADComputer -Filter 'OperatingSystem -Like "*Server*"' | Select-Object -ExpandProperty Name

# Test each server’s shares
foreach ($s in $servers) {
  Try {
	Invoke-Command -ComputerName $s -ScriptBlock { Get-SmbShare }
	Invoke-Command -ComputerName $s -ScriptBlock { Get-SmbShareAccess }
  }
  Catch { }
}