param(
    [Parameter(Mandatory = $true)]
    [string]$UserSamAccountName
)

# Retrieve the Distinguished Name of the specified AD user
$dn = (Get-ADUser -Identity $UserSamAccountName).DistinguishedName

# Get the ACL for that user object, expand its Access entries,
# filter for ExtendedRight permissions granted to that same user,
# and display a table of relevant properties.
Get-Acl "AD:$dn" |
  Select-Object -ExpandProperty Access |
  Where-Object {
    $_.ActiveDirectoryRights -match 'ExtendedRight' -and
    $_.IdentityReference -like "AIM\$UserSamAccountName"
  } |
  Format-Table IdentityReference, ObjectType, ActiveDirectoryRights, AccessControlType