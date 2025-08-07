<#
.SYNOPSIS
    Disable Kerberos pre-authentication for a given AD user and decode the existing UAC flags.

.PARAMETER ldapPath
    The full ADSI LDAP path to the user object, e.g.
    "LDAP://CN=Mario Contestabile,OU=blahblah,OU=bloop,DC=xxx,DC=yyy"

.EXAMPLE
    .\Disable-PreAuth.ps1 `
      -ldapPath "LDAP://CN=John Doe,OU=Staff,DC=contoso,DC=com"
#>

Param(
    [Parameter(Mandatory = $true, Position = 0, 
               HelpMessage = "Full ADSI path to the target user.")]
    [string]$ldapPath
)

function Decode-Uac {
    param (
        [Parameter(Mandatory = $true)]
        [int]$uac
    )

    # Hashtable of common userAccountControl flags
    $flagMap = @{
        0x00000002 = "ACCOUNTDISABLE"
        0x00000008 = "HOMEDIR_REQUIRED"
        0x00000010 = "LOCKOUT"
        0x00000020 = "PASSWD_NOTREQD"
        0x00000080 = "ENCRYPTED_TEXT_PWD_ALLOWED"
        0x00000100 = "TEMP_DUPLICATE_ACCOUNT"
        0x00000200 = "NORMAL_ACCOUNT"
        0x00000800 = "DONT_EXPIRE_PASSWD"
        0x00010000 = "MNS_LOGON_ACCOUNT"
        0x00020000 = "SMARTCARD_REQUIRED"
        0x00040000 = "TRUSTED_FOR_DELEGATION"
        0x00080000 = "NOT_DELEGATED"
        0x00100000 = "USE_DES_KEY_ONLY"
        0x00200000 = "DONT_REQ_PREAUTH"
        0x00400000 = "PASSWORD_EXPIRED"
        0x00800000 = "TRUSTED_TO_AUTH_FOR_DELEGATION"
    }

    Write-Host "`nBreakdown of userAccountControl flags:`n"
    foreach ($entry in $flagMap.GetEnumerator() | Sort-Object Key) {
        if ($uac -band $entry.Key) {
            $hex = ('0x{0:X8}' -f $entry.Key)
            Write-Host ("  {0,10} ({1})`t: {2}" -f $entry.Key, $hex, $entry.Value)
        }
    }
    Write-Host ""
}

try {
    # Bind to the user object
    $user = [ADSI]$ldapPath
    if (-not $user) {
        Write-Error "Could not bind to $ldapPath"
        exit 1
    }

    # Read current UAC
    $currentUac = $user.Properties["userAccountControl"].Value
    Write-Host "Current userAccountControl value:`t$currentUac"
    Decode-Uac -uac $currentUac

    # Define and set the DONT_REQ_PREAUTH flag (0x400000)
    $preauthFlag = 0x400000
    $newUac = $currentUac -bor $preauthFlag
    $user.Properties["userAccountControl"].Value = $newUac
    $user.SetInfo()

    Write-Host "`nKerberos preauthentication has been disabled."
    Write-Host "New userAccountControl value:`t$newUac"
    Decode-Uac -uac $newUac
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}