<#
.SYNOPSIS
  Lists members of the local Administrators group on the machine where the script runs.

.DESCRIPTION
  Uses Get-LocalGroupMember (PowerShell 5+) to retrieve group membership
  and tags each entry with the local computer name.

.EXAMPLE
  .\Get-LocalAdmins.ps1
#>

# Ensure the cmdlet exists
if (-not (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
    Write-Error "This script requires PowerShell 5+ (Get-LocalGroupMember)."
    exit 1
}

# Pull local Administrators group members
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
}
catch {
    Write-Error "Failed to query local Administrators group: $_"
    exit 1
}

# Output with computer name tagged
$admins |
  Select-Object `
    @{Name='Computer';Expression={$env:COMPUTERNAME}}, `
    Name, `
    ObjectClass