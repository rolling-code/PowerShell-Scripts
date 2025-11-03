<#
.SYNOPSIS
  Enumerate AD user objects and infer which attributes the caller can write by inspecting ACLs.

.DESCRIPTION
  ADWS-first (Get-ADUser). If ADWS fails, falls back to LDAP using System.DirectoryServices.Protocols.
  LDAP uses Negotiate/SSPI by default and reads rootDSE via the bound connection.
#>

param(
  [System.Management.Automation.PSCredential]$Credential,
  [string]$Out = "ADUsers.csv",
  [int]$PageSize = 1000,
  [string]$Dc
)

# Optional: force LDAPS+Basic for all LDAP binds (default false; Negotiate preferred)
$ForceLdaps = $false

Import-Module ActiveDirectory -ErrorAction Stop

function Report-ADConnectivityDiagnostics {
  param([string]$TargetServer, [System.Management.Automation.PSCredential]$Credential)
  Write-Host "`n==== AD Connectivity Diagnostics ====" -ForegroundColor Yellow

  if ($TargetServer) { 
	$dc = $TargetServer; Write-Host ("Using provided DC: {0}" -f $dc) 
	if ($dc -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) 
	{
		$dc = ($dc | Select-Object -First 1)
	}
	$dc = [string]$dc
	}else {
		try { $dc = (Get-ADDomainController -Discover -ErrorAction Stop).HostName; Write-Host ("Discovered DC: {0}" -f $dc) }
		catch { Write-Warning ("Get-ADDomainController discovery failed: {0}" -f $_.Exception.Message); $dc = $null }
	  }

  if ($dc) {
    try {
      $ips = [System.Net.Dns]::GetHostAddresses($dc) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }
      if ($ips) { Write-Host ("DNS resolution for {0}: {1}" -f $dc, ($ips -join ', ')) } else { Write-Warning ("No IPv4 addresses returned for {0}" -f $dc) }
    } catch { Write-Warning ("DNS resolution failed for {0}: {1}" -f $dc, $_.Exception.Message) }
  } else { Write-Host "No DC resolved; skipping DNS resolution" }

  try {
    $domain = (Get-ADDomain -ErrorAction Stop).DNSRoot
    $nl = nltest /dsgetdc:$domain 2>&1
    Write-Host "nltest /dsgetdc output:"
    $nl | ForEach-Object { Write-Host ("  {0}" -f $_) }
  } catch { Write-Warning ("nltest/Get-ADDomain failed: {0}" -f $_.Exception.Message) }

  $ports = @{ "ADWS(9389)"=9389; "LDAP(389)"=389; "LDAPS(636)"=636 }
  foreach ($k in $ports.Keys) {
    $p = $ports[$k]
    if ($dc) {
      try {
        $t = Test-NetConnection -ComputerName $dc -Port $p -InformationLevel Detailed -WarningAction SilentlyContinue
        if ($t.TcpTestSucceeded) { Write-Host ("{0} reachable to {1} (TcpTestSucceeded=True) - PingSucceeded: {2}" -f $k,$dc,$t.PingSucceeded) }
        else { Write-Warning ("{0} NOT reachable to {1}. TcpTestSucceeded={2} | TcpPort={3}" -f $k,$dc,$t.TcpTestSucceeded,$p) }
        if ($t.RemoteAddress) { Write-Host ("  RemoteAddress: {0}  NetworkInterface: {1}" -f $t.RemoteAddress, $t.InterfaceAlias) }
      } catch { Write-Warning ("Test-NetConnection failed for {0}:{1} - {2}" -f $dc,$p,$_.Exception.Message) }
    } else { Write-Host ("Skipping port test for {0} because no DC resolved" -f $k) }
  }

  if ($Credential) { Write-Host ("Credential supplied for user: {0}" -f $Credential.UserName) }
  else { Write-Host ("No explicit credential supplied; running as current Windows account: {0}" -f ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)) }

  Write-Host "==== End diagnostics ====`n" -ForegroundColor Yellow
}

function Get-CurrentPrincipalSids {
  param($Cred)
  if ($null -ne $Cred) {
    $userName = $Cred.UserName
    if ($userName -match "\\") { $parts = $userName.Split("\"); $sam = $parts[-1]; $domain = $parts[0] }
    elseif ($userName -match "@") { $sam = $userName.Split("@")[0]; $domain = $userName.Split("@")[1] }
    else { $sam = $userName; $domain = $env:USERDNSDOMAIN }

    try {
      $adUser = Get-ADUser -Identity $sam -Server $domain -Credential $Cred -Properties SID -ErrorAction Stop
      $sids = @($adUser.SID.Value)
      $groups = Get-ADPrincipalGroupMembership -Identity $adUser -Credential $Cred -ErrorAction SilentlyContinue
      foreach ($g in $groups) { $sids += $g.SID.Value }
      return $sids
    } catch {
      Write-Warning ("Could not resolve principal SIDs via Get-ADUser: {0}. Falling back to current token." -f $_.Exception.Message)
    }
  }

  $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $sids = @($currentUser.User.Value)
  foreach ($g in $currentUser.Groups) { $sids += $g.Value }
  return $sids
}

$propertyGuidMap = @{}
function Get-AttributeNameFromPropertyGuid { param($guid); if ($null -eq $guid) { return $null }; $g = $guid.ToString(); if ($propertyGuidMap.ContainsKey($g)) { return $propertyGuidMap[$g] }; return $g }

function Resolve-ADObjectDNToDirectoryEntry {
  param($distinguishedName, $Credential, [string]$TargetDC = $null, [ValidateSet("LDAP","LDAPS")][string]$Protocol = "LDAP")
  if ($TargetDC) {
    if ($Protocol -eq "LDAPS") { $ldapPath = "LDAPS://$TargetDC:636/$distinguishedName"; $authType = [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer }
    else { $ldapPath = "LDAP://$TargetDC/$distinguishedName"; $authType = [System.DirectoryServices.AuthenticationTypes]::Secure }
  } else { $ldapPath = "LDAP://$distinguishedName"; $authType = [System.DirectoryServices.AuthenticationTypes]::Secure }

  if ($null -ne $Credential) {
    $username = $Credential.UserName; $password = $Credential.GetNetworkCredential().Password
    if ($TargetDC) { $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $username, $password, $authType) } else { $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $username, $password) }
  } else {
    if ($TargetDC) { $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $null, $null, $authType) } else { $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath) }
  }
  return $de
}

function Parse-ACEForWritableProperties {
  param($ace, $principalSids)
  $result = @()
  try { $aceSid = $ace.IdentityReference.Value } catch { return $result }
  if (-not ($principalSids -contains $aceSid)) { return $result }
  $rights = $ace.ActiveDirectoryRights

  if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) {
    if ($ace.ObjectType -and ($ace.ObjectType -ne [Guid]::Empty)) { $result += Get-AttributeNameFromPropertyGuid $ace.ObjectType } else { $result += "WriteProperty" }
  }
  if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::Write) { $result += "Write" }
  if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) { $result += "GenericWrite" }
  if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) { $result += "WriteDacl" }
  if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) { $result += "WriteOwner" }
  if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
    if ($ace.ObjectType -and ($ace.ObjectType -ne [Guid]::Empty)) { $result += "ExtendedRight:" + (Get-AttributeNameFromPropertyGuid $ace.ObjectType) } else { $result += "ExtendedRight" }
  }

  return $result | Select-Object -Unique
}

# Prepare output path
if ([System.IO.Path]::IsPathRooted($Out)) { $csvPath = $Out } else { $csvPath = Join-Path -Path (Get-Location) -ChildPath $Out }
$dir = Split-Path -Path $csvPath -Parent
if (-not (Test-Path -Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
if (-not (Test-Path -Path $csvPath)) { New-Item -Path $csvPath -ItemType File -Force | Out-Null }

# Open CSV with fallback to temp if locked
$maxAttempts = 5; $attempt = 0; $useTemp = $false; $tempCsvPath = $null
while ($true) {
  try {
    $csvStream = [System.IO.File]::Open($csvPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
    $csvStream.SetLength(0)
    $csvWriter = New-Object System.IO.StreamWriter($csvStream, [System.Text.Encoding]::UTF8)
    $csvWriter.WriteLine("sAMAccountName,distinguishedName,WritableAttributes"); $csvWriter.Flush(); $csvStream.Flush()
    break
  } catch {
    $attempt++
    if ($attempt -ge $maxAttempts) {
      Write-Warning ("Unable to open target CSV {0} after {1} attempts: {2}" -f $csvPath, $attempt, $_.Exception.Message)
      Write-Host "Falling back to a temporary CSV in the same folder."
      $tempCsvPath = Join-Path -Path (Split-Path -Path $csvPath -Parent) -ChildPath ("Users_temp_{0}.csv" -f ([System.Guid]::NewGuid().ToString()))
      try {
        New-Item -Path $tempCsvPath -ItemType File -Force | Out-Null
        $csvStream = [System.IO.File]::Open($tempCsvPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
        $csvStream.SetLength(0)
        $csvWriter = New-Object System.IO.StreamWriter($csvStream, [System.Text.Encoding]::UTF8)
        $csvWriter.WriteLine("sAMAccountName,distinguishedName,WritableAttributes"); $csvWriter.Flush(); $csvStream.Flush()
        $useTemp = $true; Write-Host ("Writing to temporary CSV: {0}" -f $tempCsvPath) -ForegroundColor Yellow
        break
      } catch {
        Write-Error ("Unable to open fallback temp CSV {0}: {1}" -f $tempCsvPath, $_.Exception.Message); throw
      }
    }
    Start-Sleep -Seconds 1
  }
}

# Resolve principal SIDs
$principalSids = Get-CurrentPrincipalSids -Cred $Credential

# Determine targetDC (honor -Dc)
$targetDC = $null
if ($Dc) { $targetDC = $Dc 
} else { 
	try { 
		$dcObj = Get-ADDomainController -Discover -ErrorAction Stop
		# HostName can be an ADPropertyValueCollection; coerce to the first string
		$targetDC = ($dcObj.HostName | Select-Object -First 1)
		$targetDC = [string]$targetDC
	} catch { 
		$targetDC = $null 
	} 
}

Report-ADConnectivityDiagnostics -TargetServer $targetDC -Credential $Credential

# ADWS-first enumeration
$searcher = $null; $ldapServer = $null; $useLdaps = $false
try {
  if ($null -ne $Credential) {
    if ($targetDC) { $searcher = Get-ADUser -Filter * -Server $targetDC -Credential $Credential -Properties DistinguishedName,sAMAccountName -ResultSetSize $null -ErrorAction Stop }
    else { $searcher = Get-ADUser -Filter * -Credential $Credential -Properties DistinguishedName,sAMAccountName -ResultSetSize $null -ErrorAction Stop }
  } else {
    if ($targetDC) { $searcher = Get-ADUser -Filter * -Server $targetDC -Properties DistinguishedName,sAMAccountName -ResultSetSize $null -ErrorAction Stop }
    else { $searcher = Get-ADUser -Filter * -Properties DistinguishedName,sAMAccountName -ResultSetSize $null -ErrorAction Stop }
  }
  Write-Host "Using ADWS (Get-ADUser) for enumeration" -ForegroundColor Green
} catch {
  Write-Warning ("ADWS enumeration failed: {0}. Falling back to LDAP enumeration." -f $_.Exception.Message)

  try {
    Add-Type -AssemblyName System.DirectoryServices.Protocols

    # --- LDAP-only fallback using an explicit LdapConnection bound with Negotiate and using rootDSE baseDN ---
    if ($targetDC) { $ldapServer = $targetDC } elseif ($Dc) { $ldapServer = $Dc } else {
      $dnsDomain = $env:USERDNSDOMAIN
      if ($dnsDomain) {
        $srv = Resolve-DnsName -Type SRV "_ldap._tcp.$dnsDomain" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($srv) { $ldapServer = $srv.NameTarget.TrimEnd('.') } else { $ldapServer = $dnsDomain }
      } else { throw "Could not determine LDAP server; supply -Dc or run on a joined machine." }
    }

    $useLdaps = $ForceLdaps
    $ldapPort = if ($useLdaps) { 636 } else { 389 }

    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($ldapServer, [int]$ldapPort, $false, $false)
    $ldapConn = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    $ldapConn.SessionOptions.ProtocolVersion = 3
    $ldapConn.Timeout = New-TimeSpan -Seconds 30
    if ($useLdaps) { $ldapConn.SessionOptions.SecureSocketLayer = $true }

    if ($null -ne $Credential) {
      $credUser = $Credential.UserName
      $netCred = $Credential.GetNetworkCredential()
      $username = $netCred.UserName; $password = $netCred.Password; $domain = $null
      if ($credUser -match "\\") { $parts = $credUser.Split("\"); $domain = $parts[0]; $username = $parts[1] }
      elseif ($credUser -match "@") { $username = $credUser.Split("@")[0]; $domain = $credUser.Split("@")[1] }

      if (-not $useLdaps) {
        $ldapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        if ($domain) { $ldapConn.Credential = New-Object System.Net.NetworkCredential($username, $password, $domain) }
        else { $ldapConn.Credential = New-Object System.Net.NetworkCredential($username, $password) }
      } else {
        $ldapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
        if ($domain) { $ldapConn.Credential = New-Object System.Net.NetworkCredential($username, $password, $domain) }
        else { $ldapConn.Credential = New-Object System.Net.NetworkCredential($username, $password) }
      }
    } else {
      $ldapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    }

    try {
      $ldapConn.Bind()
    } catch {
      throw ("LDAP Bind failed to {0}:{1} using AuthType {2}: {3}" -f $ldapServer, $ldapPort, $ldapConn.AuthType, $_.Exception.Message)
    }

    $rootRequest = New-Object System.DirectoryServices.Protocols.SearchRequest("", "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Base, "defaultNamingContext")
    $rootResp = $ldapConn.SendRequest($rootRequest)
    if ($rootResp -and $rootResp.Entries.Count -gt 0) {
      $baseDn = $rootResp.Entries[0].Attributes["defaultNamingContext"][0]
    } else {
      throw "Unable to obtain defaultNamingContext via LDAP rootDSE"
    }

    $pageSize = [int]$PageSize
    $cookie = $null
    $searchFilter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=*))"
    $attributes = @("distinguishedName","sAMAccountName")
    $searcherResults = @()

    do {
      $paged = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
      if ($cookie) { $paged.Cookie = $cookie }
      $request = New-Object System.DirectoryServices.Protocols.SearchRequest($baseDn, $searchFilter, [System.DirectoryServices.Protocols.SearchScope]::Subtree, $attributes)
      $request.Controls.Add($paged)
      $response = $ldapConn.SendRequest($request)

      foreach ($entry in $response.Entries) {
        # Read attributes explicitly and coerce to string to avoid boolean-presence issues
        $dn = $null
        if ($entry.Attributes["distinguishedName"] -and $entry.Attributes["distinguishedName"].Count -gt 0) {
          $dn = [string]$entry.Attributes["distinguishedName"][0]
        } elseif ($entry.DistinguishedName) {
          $dn = [string]$entry.DistinguishedName
        }

        $sam = $null
        if ($entry.Attributes["sAMAccountName"] -and $entry.Attributes["sAMAccountName"].Count -gt 0) {
          $sam = [string]$entry.Attributes["sAMAccountName"][0]
        }

        # Build a stable identifier string for logging (avoid -or which can return booleans)
        if ($sam -and -not [string]::IsNullOrWhiteSpace($sam)) { $logId = $sam } elseif ($dn -and -not [string]::IsNullOrWhiteSpace($dn)) { $logId = $dn } else { $logId = '<no identifier>' }

        $searcherResults += [PSCustomObject]@{ sAMAccountName = $sam; DistinguishedName = $dn; LogId = $logId }
      }

      $cookie = ($response.Controls | Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] } | ForEach-Object { $_.Cookie }) | Select-Object -First 1
    } while ($cookie -and $cookie.Length -gt 0)

    $searcher = $searcherResults
    Write-Host ("LDAP enumeration complete (server: {0}, port: {1}, LDAPS: {2})" -f $ldapServer, $ldapPort, $useLdaps) -ForegroundColor Green
    # --- end LDAP fallback block ---
  } catch {
    Write-Error ("LDAP fallback also failed: {0}" -f $_.Exception.Message)
    throw
  }
}

# --- Begin replacement processing loop body ---
$count = 0
foreach ($u in $searcher) {
  try {
    if ($null -eq $u) {
      Write-Warning "Skipping null search result object"
      continue
    }

    # Defensive field reads
    $sam = $null; $dn = $null; $logId = $null; $upn = $null
    if ($u.PSObject.Properties.Match('sAMAccountName')) { $sam = $u.sAMAccountName }
    if ($u.PSObject.Properties.Match('DistinguishedName')) { $dn = $u.DistinguishedName }
    if ($u.PSObject.Properties.Match('LogId')) { $logId = $u.LogId }
    if ($u.PSObject.Properties.Match('userPrincipalName')) { $upn = $u.userPrincipalName }

    # Build a reliable identifier: prefer sAMAccountName, then userPrincipalName, then DN, then LogId placeholder
    if ($sam -and -not [string]::IsNullOrWhiteSpace($sam)) { $identifier = $sam }
    elseif ($upn -and -not [string]::IsNullOrWhiteSpace($upn)) { $identifier = $upn }
    elseif ($dn -and -not [string]::IsNullOrWhiteSpace($dn)) { $identifier = $dn }
    elseif ($logId -and -not [string]::IsNullOrWhiteSpace($logId)) { $identifier = $logId }
    else { $identifier = '<no identifier>' }

    if ([string]::IsNullOrWhiteSpace($sam)) { Write-Warning ("Processing entry with empty sAMAccountName; identifier: {0}" -f $identifier) }
    Write-Host ("Processing {0}" -f $identifier) -ForegroundColor Cyan

    if ([string]::IsNullOrWhiteSpace($dn)) {
      Write-Warning ("Skipping {0} because DistinguishedName is empty" -f $identifier)
      continue
    }

    # Bind to object and safely obtain security descriptor
    try {
      if ($ldapServer) {
        $protocol = if ($useLdaps) { "LDAPS" } else { "LDAP" }
        $de = Resolve-ADObjectDNToDirectoryEntry -distinguishedName $dn -Credential $Credential -TargetDC $ldapServer -Protocol $protocol
      } else {
        $de = Resolve-ADObjectDNToDirectoryEntry -distinguishedName $dn -Credential $Credential
      }
    } catch {
      Write-Warning ("Could not bind to DN {0}: {1}" -f $dn, $_.Exception.Message)
      # Write a CSV line indicating we could not read ACLs, but still record the object
      $csvLine = '"' + ($identifier -replace '"','""') + '","' + ($dn -replace '"','""') + '","' + "ERROR:BindFailed" + '"'
      $csvWriter.WriteLine($csvLine); $csvWriter.Flush(); $csvStream.Flush()
      continue
    }

    if ($null -eq $de) {
      Write-Warning ("DirectoryEntry is null for {0}" -f $identifier)
      $csvLine = '"' + ($identifier -replace '"','""') + '","' + ($dn -replace '"','""') + '","' + "ERROR:NoDirectoryEntry" + '"'
      $csvWriter.WriteLine($csvLine); $csvWriter.Flush(); $csvStream.Flush()
      continue
    }

    # Safely access ObjectSecurity; if unavailable, record and continue
    $objSecurity = $null
    try { $objSecurity = $de.ObjectSecurity } catch { $objSecurity = $null }

    if ($null -eq $objSecurity) {
      Write-Warning ("ObjectSecurity unavailable for {0}" -f $identifier)
      $csvLine = '"' + ($identifier -replace '"','""') + '","' + ($dn -replace '"','""') + '","' + "ERROR:ObjectSecurityUnavailable" + '"'
      $csvWriter.WriteLine($csvLine); $csvWriter.Flush(); $csvStream.Flush()
      continue
    }

    # Get ACEs defensively
    $aces = $null
    try { $aces = $objSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) } catch { $aces = $null }

    if ($null -eq $aces -or $aces.Count -eq 0) {
      # No ACEs to inspect; write an empty-writable row so the object is present in CSV
      $csvLine = '"' + ($identifier -replace '"','""') + '","' + ($dn -replace '"','""') + '","' + "" + '"'
      $csvWriter.WriteLine($csvLine); $csvWriter.Flush(); $csvStream.Flush()
      $count++; continue
    }

    $writable = @()
    foreach ($ace in $aces) {
      if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
      $aceResults = Parse-ACEForWritableProperties -ace $ace -principalSids $principalSids
      if ($aceResults) { foreach ($r in $aceResults) { $writable += $r } }
    }

    $writable = $writable | Select-Object -Unique

    # Always write a CSV row even if writable is empty; use identifier when sAMAccountName not present
    $csvSam = if ($sam -and -not [string]::IsNullOrWhiteSpace($sam)) { $sam } else { $identifier }
    $csvLine = '"' + ($csvSam -replace '"','""') + '","' + ($dn -replace '"','""') + '","' + ($writable -join ';') + '"'
    $csvWriter.WriteLine($csvLine); $csvWriter.Flush(); $csvStream.Flush()

    $count++
  } catch {
    Write-Warning ("Skipping {0} due to error: {1}" -f ($u.sAMAccountName -or '<no sAM>'), $_.Exception.Message)
    continue
  }
}
# --- End replacement processing loop body ---

$csvWriter.Close(); $csvStream.Close()

if ($useTemp -and $tempCsvPath) {
  try { Move-Item -Path $tempCsvPath -Destination $csvPath -Force; Write-Host ("Replaced target CSV with temporary CSV: {0}" -f $csvPath) -ForegroundColor Green }
  catch { Write-Warning ("Could not replace target CSV ({0}). Temporary CSV retained at: {1}" -f $csvPath,$tempCsvPath); Write-Host ("Done. Processed {0} users. Temporary CSV: {1}" -f $count,$tempCsvPath) -ForegroundColor Yellow; exit 0 }
} else {
  Write-Host ("Done. Processed {0} users. CSV output: {1}" -f $count,$csvPath) -ForegroundColor Green
}