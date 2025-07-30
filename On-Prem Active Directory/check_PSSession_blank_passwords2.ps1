<#
.SYNOPSIS
  Tests whether AD accounts can open a PSSession with a blank password.

.PARAMETER DomainFqdn
  Your AD domain’s DNS name (e.g. example.net).

.PARAMETER Users
  An array of names to test. Can be display names or logon names.

.EXAMPLE
  .\Test-BlankPwdSessions.ps1 `
    -DomainFqdn example.net `
    -Users "Stevie Wonder", "mcontestabile"
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]   $DomainFqdn,
  [Parameter(Mandatory)][string[]] $Users
)

Import-Module ActiveDirectory -ErrorAction Stop

foreach ($u in $Users) {
    # Attempt to resolve a DisplayName -> SamAccountName/UPN
    $adUser = Get-ADUser -Filter "Name -eq '$u'" `
                        -Properties SamAccountName, UserPrincipalName `
                        -ErrorAction SilentlyContinue

    if ($adUser) {
        # Prefer UPN (alice@contoso.com), fallback to DOMAIN\Sam
        $logon = if ($adUser.UserPrincipalName) {
            $adUser.UserPrincipalName
        } else {
            "$DomainFqdn\$($adUser.SamAccountName)"
        }
    }
    else {
        # Not found as a display name; assume $u is already a logon name
        # You could test for a '@' and treat it as UPN automatically
        $logon = if ($u -match '@') {
            $u
        } else {
            "$DomainFqdn\$u"
        }
    }

    # Build an empty SecureString for blank-password testing
    $sec = New-Object System.Security.SecureString

    $cred = New-Object System.Management.Automation.PSCredential(
        $logon,
        $sec
    )

    try {
        $sess = New-PSSession -ComputerName $DomainFqdn `
                              -Credential $cred `
                              -ErrorAction Stop
        Write-Host "[+] $logon can open PSSession (blank password?)" `
            -ForegroundColor Green
        Remove-PSSession $sess
    }
    catch {
        Write-Host "[-] $logon cannot open PSSession" -ForegroundColor Red
    }
}