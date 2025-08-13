<#
.SYNOPSIS
  Show ExtendedRight ACEs on a user’s AD object that are granted to that same user.

.PARAMETER UserName
  The account to inspect: 'DOMAIN\sam', 'sam', or UPN (user@domain).

.REQUIREMENTS
  ActiveDirectory module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserName
)

Import-Module ActiveDirectory -ErrorAction Stop

function Resolve-User {
    param([string]$InputName)

    # Try DOMAIN\sam -> SID via NTAccount first (fast, exact)
    if ($InputName -match '^[^\\]+\\[^\\]+$') {
        $parts = $InputName.Split('\',2)
        try {
            $sidObj = (New-Object System.Security.Principal.NTAccount($parts[0], $parts[1])).Translate([System.Security.Principal.SecurityIdentifier])
            $sid = $sidObj.Value
            $u = Get-ADUser -Identity $sid -Properties * -ErrorAction Stop
            return $u
        } catch {}
    }

    # UPN path
    if ($InputName -like '*@*') {
        $u = Get-ADUser -Filter "UserPrincipalName -eq '$InputName'" -Properties * -ErrorAction SilentlyContinue
        if ($u) { return $u }
    }

    # Plain samAccountName path
    try {
        $u = Get-ADUser -Identity $InputName -Properties * -ErrorAction Stop
        if ($u) { return $u }
    } catch {
        $u = Get-ADUser -Filter "SamAccountName -eq '$InputName'" -Properties * -ErrorAction SilentlyContinue
        if ($u) { return $u }
    }

    throw "Could not resolve user '$InputName' in Active Directory."
}

$user = Resolve-User -InputName $UserName
$dn   = $user.DistinguishedName

# Resolve the user's SID for exact IdentityReference matching
$userSid = (New-Object System.Security.Principal.NTAccount($user.SID.Translate([System.Security.Principal.NTAccount])).Translate([System.Security.Principal.SecurityIdentifier])).Value
# Simplify: just take SID from the user object
$userSid = $user.SID.Value

# Pull ACL and filter to ExtendedRight ACEs granted to this user (SID-exact)
$aces = Get-Acl "AD:$dn" |
    Select-Object -ExpandProperty Access |
    ForEach-Object {
        # Translate each ACE IdentityReference to SID for exact comparison
        $aceSid = $null
        try { $aceSid = ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])).Value } catch {}
        [PSCustomObject]@{
            IdentityReference     = $_.IdentityReference
            IdentitySid           = $aceSid
            ObjectType            = $_.ObjectType
            ActiveDirectoryRights = $_.ActiveDirectoryRights
            AccessControlType     = $_.AccessControlType
            InheritanceType       = $_.InheritanceType
            IsInherited           = $_.IsInherited
        }
    } | Where-Object {
        $_.IdentitySid -eq $userSid -and $_.ActiveDirectoryRights -match 'ExtendedRight'
    }

if (-not $aces) {
    Write-Host "No ExtendedRight ACEs on this user object granted to $($user.SamAccountName)." -ForegroundColor Yellow
    return
}

$aces | Format-Table IdentityReference, IdentitySid, ObjectType, ActiveDirectoryRights, AccessControlType
