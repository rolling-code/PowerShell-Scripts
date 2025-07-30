Param(
  [Parameter(Mandatory, Position=0)][string]$Username,
  [Parameter(Mandatory, Position=1)][string]$Domain
)

Import-Module ActiveDirectory

$target = $Username 
$root   = $Domain   

Get-ADObject -LDAPFilter '(objectClass=*)' -SearchBase $root `
  -Properties nTSecurityDescriptor |
  ForEach-Object {
    $_.nTSecurityDescriptor.Access |
      Where-Object { $_.IdentityReference -eq $target } |
      ForEach-Object {
        [PSCustomObject]@{
          ObjectDN   = $_.PSParentPath
          Rights     = $_.ActiveDirectoryRights
          Inherited  = $_.IsInherited
          Type       = $_.AccessControlType
        }
      }
  } | Format-List ObjectDN, Rights, Inherited 