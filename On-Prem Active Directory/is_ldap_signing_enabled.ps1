param (
    [Parameter(Mandatory=$true)]
    [string]$LdapServer,

    [Parameter(Mandatory=$true)]
    [string]$UserUPN,

    [Parameter(Mandatory=$true)]
    [SecureString]$Password
)

function Test-SimpleBind {
    param(
        [string]$Server,
        [int]$Port,
        [bool]$UseStartTls
    )

    # Build LDAP identifier and credentials
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port, $false, $false)
    $creds      = New-Object System.Management.Automation.PSCredential($UserUPN, $Password)
    $ldap       = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier, $creds)

    $ldap.AuthType                 = [System.DirectoryServices.Protocols.AuthType]::Basic
    $ldap.SessionOptions.ProtocolVersion = 3

    if ($UseStartTls) {
        try {
            $ldap.SessionOptions.StartTransportLayerSecurity($null)
        }
        catch {
            return @{ Success = $false; Code = $_.Exception.ErrorCode; Phase = 'StartTLS' }
        }
    }
    elseif ($Port -eq 636) {
        $ldap.SessionOptions.SecureSocketLayer = $true
    }

    try {
        $ldap.Bind()
        return @{ Success = $true; Code = 0; Phase = 'Bind' }
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        # Make sure we get the AD error code
        $ec = if ($_.Exception.ErrorCode) { $_.Exception.ErrorCode } else { $_.ErrorCode }
        return @{ Success = $false; Code = $ec; Phase = 'Bind' }
    }
}

# Run tests
$plain = Test-SimpleBind -Server $LdapServer -Port 389 -UseStartTls:$false
$tls   = Test-SimpleBind -Server $LdapServer -Port 389 -UseStartTls:$true
$ldaps = Test-SimpleBind -Server $LdapServer -Port 636 -UseStartTls:$false

# Output
Write-Host "Plain simple bind (389):"    ($plain.Success  ? 'Allowed' : "Rejected (Code $($plain.Code))")
Write-Host "StartTLS simple bind (389):" ($tls.Success    ? 'Allowed' : "Rejected (Code $($tls.Code))")
Write-Host "LDAPS simple bind (636):"     ($ldaps.Success  ? 'Allowed' : "Rejected (Code $($ldaps.Code))")

# Recommendations
if ($plain.Success) {
    Write-Host "`nRecommendation: Clear-text binds are allowed."
    Write-Host " • Set ‘Domain controller: LDAP server signing requirements’ to Require signing."
    Write-Host " • Enforce TLS (StartTLS or LDAPS) for credential encryption."
}
elseif ($plain.Code -eq 8) {
    Write-Host "`nRecommendation: Your DC enforces LDAP signing."
    Write-Host " • Confirm GPO ‘LDAP server signing requirements’ = Require signing."
    Write-Host " • Ensure StartTLS/LDAPS is configured to avoid clear-text rejection."
}
else {
    Write-Host "`nNote: Plain bind failed with unexpected code $($plain.Code)."
    Write-Host "Check your credentials, account status, network, or referrals."
}

if (-not $tls.Success) {
    Write-Host "`nNote: StartTLS failed (Code $($tls.Code))."
    Write-Host " • Verify the DC has a valid TLS certificate installed."
}

if (-not $ldaps.Success) {
    Write-Host "`nNote: LDAPS failed (Code $($ldaps.Code))."
    Write-Host " • Ensure port 636 is open and the client trusts the DC certificate."
}