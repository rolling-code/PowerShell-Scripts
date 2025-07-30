<#
.SYNOPSIS
  Tests AD accounts for blank or username-equal passwords and reports results.

.PARAMETER DomainFqdn
  Your AD domain’s DNS name (e.g. contoso.com).

.EXAMPLE
  .\Test-WeakPasswords.ps1 -DomainFqdn contoso.com
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateNotNullOrEmpty()]
  [string]$DomainFqdn
)

# Ensure AD cmdlets are available
if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
  Write-Error "ActiveDirectory module not found. Install RSAT or import the module."
  exit 1
}

# Get all users flagged PasswordNotRequired
$users = Get-ADUser -Filter 'PasswordNotRequired -eq $true' `
                   -Server $DomainFqdn `
                   -Properties Name,SamAccountName |
         Select-Object Name,SamAccountName

# Load the .NET type for credential validation
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

# Create a domain context against which to test credentials
$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
  [System.DirectoryServices.AccountManagement.ContextType]::Domain,
  $DomainFqdn
)

# Test each user and collect results
$results = foreach ($u in $users) {
  $sam = $u.SamAccountName

  # Test blank password
  $blankOk = $ctx.ValidateCredentials($sam, '')

  # Test password = username
  $userPwdOk = $ctx.ValidateCredentials($sam, $sam)

  [PSCustomObject]@{
    Name                 = $u.Name
    SamAccountName       = $sam
    BlankPassword        = if ($blankOk) { 'Pass' } else { 'Fail' }
    PasswordEqualsName   = if ($userPwdOk) { 'Pass' } else { 'Fail' }
  }
}

# Display as table
$results |
  Sort-Object Name |
  Format-Table Name, SamAccountName, BlankPassword, PasswordEqualsName -AutoSize