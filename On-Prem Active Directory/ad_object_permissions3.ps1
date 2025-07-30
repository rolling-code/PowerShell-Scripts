[CmdletBinding()]
Param(
  [Parameter(Mandatory, Position=0)][string]$Username,
  [Parameter(Mandatory, Position=1)][string]$Domain
)

Import-Module ActiveDirectory

# Build a principals array: user + all groups
$acctName = $Username.Split('\')[-1]
$principals = @(
  $acctName,
  ( Get-ADPrincipalGroupMembership -Identity $acctName |
      Select-Object -ExpandProperty SamAccountName )
) |
  ForEach-Object { $_.ToLower() } |
  Sort-Object -Unique



$root = $Domain

Write-Host "Searching under: $root" -ForegroundColor Cyan
Write-Host "Matching principals: $($principals -join ', ')" -ForegroundColor Cyan

$matches = Get-ADObject -Filter * -SearchBase $root `
    -Properties nTSecurityDescriptor `
    -ErrorAction SilentlyContinue |
  ForEach-Object {
    $dn = $_.DistinguishedName

    # Filter ACL entries for any principal in our list
    $aceMatches = $_.nTSecurityDescriptor.Access |
      Where-Object {
        $_.IdentityReference           -and
        $_.IdentityReference.Value     -and
        (
          # Take the right-hand side of the backslash, lowercase it,
          # then see if it lives in $principals
          $principals -contains
            (($_.IdentityReference.Value -split '\\')[-1]).ToLower()
        )
      }

    # Emit a custom object for each match
    foreach ($ace in $aceMatches) {
      [PSCustomObject]@{
        ObjectDN          = $dn
        Principal         = $ace.IdentityReference.Value
        Rights            = $ace.ActiveDirectoryRights
        AccessControlType = $ace.AccessControlType
        IsInherited       = $ace.IsInherited
      }
    }
  }

# Output results
if ($matches) {
  #$matches | Format-Table -AutoSize
  #Write-Host "Total ACE entries matched: $($matches.Count)" -ForegroundColor Green
  
  #$matches | Format-Table ObjectDN,Principal,Rights -AutoSize -Wrap
  #Write-Host "Total ACE entries matched: $($matches.Count)" -ForegroundColor Green
  
  $matches | Format-List ObjectDN,Principal,Rights
  Write-Host "Total ACE entries matched: $($matches.Count)" -ForegroundColor Green
}
else {
  Write-Host "No ACEs found for $Username under $root" -ForegroundColor Yellow
}