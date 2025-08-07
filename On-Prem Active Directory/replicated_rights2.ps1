[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$UserAccountName,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$SearchBase
)

Import-Module ActiveDirectory

Start-Transcript -Path "./replicated_rights2.log" -Append

Write-Verbose "Starting scan for '$UserAccountName' under '$SearchBase'"

# Retrieve every AD object under the supplied SearchBase
$allObjects = Get-ADObject `
    -LDAPFilter '(objectClass=*)' `
    -SearchBase $SearchBase `
    -Properties DistinguishedName, nTSecurityDescriptor

$totalCount   = $allObjects.Count
$currentIndex = 0

foreach ($obj in $allObjects) {
    $currentIndex++

    foreach ($ace in $obj.nTSecurityDescriptor.Access) {
        $idValue = $ace.IdentityReference.Value

        if ([string]::IsNullOrWhiteSpace($idValue)) { continue }

        # Check for the target user and specific rights
        if (
            $idValue -eq $UserAccountName -and
            (
                ($ace.ActiveDirectoryRights -band 'GenericAll')    -or
                ($ace.ActiveDirectoryRights -band 'WriteProperty') -or
                ($ace.ActiveDirectoryRights -band 'ExtendedRight')
            )
        ) {
            # Output matching ACE as a custom object
            [PSCustomObject]@{
                ObjectDN  = $obj.DistinguishedName
                Rights    = $ace.ActiveDirectoryRights
                Type      = $ace.AccessControlType
                Inherited = $ace.IsInherited
            }
        }
    }
}

# Move to the next line after all dots have been printed
Write-Host ""

Stop-Transcript