
<# 
.SYNOPSIS
  Checks if a low-privileged user can create an A record in an AD-integrated DNS zone via LDAP.
  If the add succeeds, your zone ACL likely allows low-priv writes (not recommended per Depth Security guidance).

.DESCRIPTION
  - TCP preflight (389/636) with clear diagnostics.
  - LDAP/LDAPS bind (Negotiate).
  - Robust RootDSE resolution:
      * Try S.DS.Protocols RootDSE (defaultNamingContext/rootDomainNamingContext/namingContexts).
      * Fallback to pure .NET DirectoryEntry("LDAP://<server>:<port>/RootDSE") for PS7.
      * Or pass -DomainNC explicitly to skip discovery.  (RootDSE/namingContexts per MS-ADTS.)
  - Finds the DNS zone under:
      1) CN=MicrosoftDNS,DC=DomainDnsZones,<domainNC>
      2) CN=MicrosoftDNS,DC=ForestDnsZones,<domainNC>
      3) CN=MicrosoftDNS,CN=System,<domainNC>   (# legacy container)
  - Reads the zone SOA serial; builds a spec-compliant dnsRecord (A) blob per MS-DNSP §2.3.2.2.
  - Attempts to add a single-label test record; reports PASS (denied) or FAIL (created).
  - Deletes the record by default (use -Keep to retain).
  - Optional: -ListZones to enumerate all discovered zones (read-only).

.PARAMETER DcHost
  DC hostname or IP to connect to.

.PARAMETER Port
  LDAP port. Default 389. Use 636 with -UseSSL.

.PARAMETER UseSSL
  Use LDAPS (TLS). Requires a DC certificate trusted by the client (or LAB ONLY: -SkipCertValidation).

.PARAMETER SkipCertValidation
  LAB ONLY. Skips LDAPS certificate validation.

.PARAMETER DomainNC
  Optional. Explicit domain naming context DN (e.g., 'DC=aimfire,DC=net').

.PARAMETER Zone
  Optional. FQDN of the forward lookup zone (e.g. aimfire.net). If omitted, derived from the domain NC.

.PARAMETER RecordIp
  IPv4 address for the test A record. Default: 127.0.0.1.

.PARAMETER Keep
  Keep the test record (skip cleanup).

.PARAMETER ListZones
  Enumerate zones under all three containers and exit (no write test).

.PARAMETER LogPath
  Optional transcript path to capture all output.

.NOTES
  - RDN attribute for dnsNode is Domain-Component -> you must include dc=<label> on create.  (Schema) 
  - S.DS.Protocols DirectoryAttribute accepts only string/byte[]/Uri values. (Booleans must be "TRUE"/"FALSE" strings if used.)
  - dNSTombstoned is system-managed for DNS deletions; omit on create.

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$DcHost,

  [int]$Port = 389,

  [switch]$UseSSL,

  [switch]$SkipCertValidation,

  [string]$DomainNC,

  [string]$Zone,

  [string]$RecordIp = '127.0.0.1',

  [switch]$Keep,

  [switch]$ListZones,

  [string]$LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($LogPath) {
  try { Start-Transcript -Path $LogPath -Append -ErrorAction Stop | Out-Null } catch { Write-Warning "Could not start transcript: $($_.Exception.Message)" }
}

#---------------------------
# Utilities / Logging
#---------------------------
Add-Type -AssemblyName System.DirectoryServices.Protocols
try { Add-Type -AssemblyName System.DirectoryServices } catch { }  # for DirectoryEntry RootDSE fallback

function Write-Step([string]$msg){ Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-Detail([string]$msg){ Write-Host "    $msg" -ForegroundColor Gray }
function Write-OK([string]$msg){ Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-FAIL([string]$msg){ Write-Host "[FAIL] $msg" -ForegroundColor Red }

#---------------------------
# Connectivity preflight
#---------------------------
Write-Step "Connectivity preflight"
try {
  $client = [System.Net.Sockets.TcpClient]::new()
  $async  = $client.BeginConnect($DcHost, $Port, $null, $null)
  if (-not $async.AsyncWaitHandle.WaitOne(3000)) { throw ("TCP {0}:{1} not reachable (timeout)" -f $DcHost, $Port) }
  $client.EndConnect($async)
  $client.Close()
  Write-OK ("TCP {0}:{1} reachable" -f $DcHost, $Port)
} catch {
  Write-FAIL $_.Exception.Message
  Write-Host "Hints:"
  Write-Detail ("- Verify DC/port ({0}:{1}) is correct and reachable (firewall/VPN)." -f $DcHost, $Port)
  Write-Detail "- If your org enforces LDAPS, retry with: -UseSSL -Port 636"
  Write-Detail "- If you used an IP and your environment requires Kerberos only, try an FQDN."
  throw
}

#---------------------------
# LDAP Connect & Bind
#---------------------------
Write-Step "LDAP bind"
try {
  $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($DcHost, $Port, $false, $false)
  $conn = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
  $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate

  if ($UseSSL) {
    Write-Detail "Setting SSL (LDAPS)"
    $conn.SessionOptions.SecureSocketLayer = $true
    if ($SkipCertValidation) {
      Write-Warning "Skipping server certificate validation (LAB ONLY)."
      $Callback = { param($connection,$certificate) return $true }
      $conn.SessionOptions.VerifyServerCertificate = $Callback
    }
  }

  try { $conn.SessionOptions.Sealing = $true; $conn.SessionOptions.Signing = $true } catch {}
  Write-Detail ("Binding as current user to {0}:{1} ..." -f $DcHost, $Port)
  $conn.Bind()
  Write-OK "LDAP bind succeeded"
} catch {
  Write-FAIL ("LDAP bind failed: {0}" -f $_.Exception.Message)
  Write-Host "Common causes & suggestions:"
  Write-Detail "- DC requires LDAPS: retry with -UseSSL -Port 636 (ensure trusted DC certificate)."
  Write-Detail "- TLS trust issue: import issuing CA to client Trusted Root; or LAB ONLY use -SkipCertValidation."
  Write-Detail "- Firewall/IPS blocking LDAP/LDAPS."
  throw
}

#---------------------------
# RootDSE discovery (protocol + DirectoryEntry fallback + -DomainNC override)
#---------------------------
function Get-RootDse-Protocols {
  param([System.DirectoryServices.Protocols.LdapConnection]$Conn)
  $req = [System.DirectoryServices.Protocols.SearchRequest]::new(
    "", "(objectClass=*)",
    [System.DirectoryServices.Protocols.SearchScope]::Base,
    @("defaultNamingContext","rootDomainNamingContext","configurationNamingContext","namingContexts")
  )
  $res = $Conn.SendRequest($req)
  if ($res.Entries.Count -lt 1) { throw "RootDSE (protocol) returned no entries." }
  return $res.Entries[0].Attributes
}

function Get-Attr {
  param([System.DirectoryServices.Protocols.DirectoryAttributeCollection]$Attrs,[string]$Name)
  try { $v = $Attrs[$Name]; if ($v) { return $v } } catch {}
  return $null
}

function Get-RootDse-DirectoryEntry {
  param([string]$Server,[int]$Port)
  $ldapPath = ("LDAP://{0}:{1}/RootDSE" -f $Server, $Port)
  $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
  $null = $de.NativeObject  # bind
  $map = @{}
  foreach ($p in @("defaultNamingContext","rootDomainNamingContext","configurationNamingContext","namingContexts")) {
    try {
      $val = $de.Properties[$p].Value
      if ($val) { $map[$p] = @($val) }
    } catch {}
  }
  return $map
}

function Select-DomainNC {
  param(
    [System.DirectoryServices.Protocols.DirectoryAttributeCollection]$Attrs,
    [hashtable]$DeMap,
    [string]$DomainNCOverride
  )

  if ($DomainNCOverride) { return $DomainNCOverride, 'Parameter:DomainNC' }

  $v = Get-Attr $Attrs 'defaultNamingContext'
  if ($v -and $v.Count -gt 0) { return [string]$v[0], 'defaultNamingContext' }

  $v = Get-Attr $Attrs 'rootDomainNamingContext'
  if ($v -and $v.Count -gt 0) { return [string]$v[0], 'rootDomainNamingContext' }

  $v = Get-Attr $Attrs 'namingContexts'
  if ($v -and $v.Count -gt 0) {
    $cand = @($v) |
      Where-Object { $_ -match '^DC=' } |
      Where-Object { $_ -notmatch '^CN=Schema' -and $_ -notmatch '^CN=Configuration' } |
      Where-Object { $_ -notmatch 'DC=DomainDnsZones' -and $_ -notmatch 'DC=ForestDnsZones' } |
      Select-Object -First 1
    if ($cand) { return [string]$cand, 'namingContexts' }
  }

  if ($DeMap) {
    if ($DeMap.ContainsKey('defaultNamingContext')) { return $DeMap['defaultNamingContext'][0], 'DirectoryEntry:defaultNamingContext' }
    if ($DeMap.ContainsKey('rootDomainNamingContext')) { return $DeMap['rootDomainNamingContext'][0], 'DirectoryEntry:rootDomainNamingContext' }
    if ($DeMap.ContainsKey('namingContexts')) {
      $cand = @($DeMap['namingContexts']) |
        Where-Object { $_ -match '^DC=' } |
        Where-Object { $_ -notmatch '^CN=Schema' -and $_ -notmatch '^CN=Configuration' } |
        Where-Object { $_ -notmatch 'DC=DomainDnsZones' -and $_ -notmatch 'DC=ForestDnsZones' } |
        Select-Object -First 1
      if ($cand) { return $cand, 'DirectoryEntry:namingContexts' }
    }
  }

  throw "Could not determine domain naming context from RootDSE."
}

Write-Step "Discovering naming contexts (RootDSE)"
$root = Get-RootDse-Protocols -Conn $conn
$ncProto = @( Get-Attr $root 'namingContexts' )
if ($ncProto.Count -gt 0) { Write-Verbose ("RootDSE namingContexts (protocol): {0}" -f ($ncProto -join '; ')) }
else { Write-Verbose "RootDSE namingContexts (protocol): (none)" }

$deMap = $null
try {
  $deMap = Get-RootDse-DirectoryEntry -Server $DcHost -Port $Port
  if ($deMap.ContainsKey('namingContexts')) {
    Write-Verbose ("RootDSE namingContexts (DirectoryEntry): {0}" -f ($deMap['namingContexts'] -join '; '))
  } else {
    Write-Verbose "RootDSE namingContexts (DirectoryEntry): (none)"
  }
} catch {
  Write-Verbose ("DirectoryEntry RootDSE fallback failed: {0}" -f $_.Exception.Message)
}

$defaultNC, $ncSource = Select-DomainNC -Attrs $root -DeMap $deMap -DomainNCOverride $DomainNC
Write-OK ("Using domain NC from {0} = {1}" -f $ncSource, $defaultNC)

function Convert-DNToDnsName {
  param([string]$DN)
  $parts = @()
  foreach ($m in ([regex]::Matches($DN, 'DC=([^,]+)', 'IgnoreCase'))) { $parts += $m.Groups[1].Value }
  return ($parts -join '.').ToLower()
}

$domainName = if ($PSBoundParameters.ContainsKey('Zone') -and $Zone) { $Zone } else { Convert-DNToDnsName $defaultNC }
Write-OK ("Zone to test = {0}" -f $domainName)

#---------------------------
# Zone discovery (DomainDnsZones, ForestDnsZones, legacy CN=System)
#---------------------------
function Get-ZoneDN {
  param(
    [System.DirectoryServices.Protocols.LdapConnection]$Conn,
    [string]$ZoneFqdn,
    [string]$DefaultNC
  )

  $basesTried = @()
  $bases = @(
    ("CN=MicrosoftDNS,DC=DomainDnsZones,{0}" -f $DefaultNC),
    ("CN=MicrosoftDNS,DC=ForestDnsZones,{0}" -f $DefaultNC),
    ("CN=MicrosoftDNS,CN=System,{0}" -f $DefaultNC)   # legacy container
  )
  foreach ($base in $bases) {
    $basesTried += $base
    Write-Verbose ("Searching base: {0}" -f $base)
    $filter = "(&(objectClass=dnsZone)(|(name=$ZoneFqdn)(dc=$ZoneFqdn)))"
    $req = [System.DirectoryServices.Protocols.SearchRequest]::new(
      $base,
      $filter,
      [System.DirectoryServices.Protocols.SearchScope]::Subtree,
      @("distinguishedName","name","dc")
    )
    try {
      $res = $Conn.SendRequest($req)
      if ($res.Entries.Count -ge 1) {
        return $res.Entries[0].DistinguishedName, $basesTried
      }
    } catch {
      Write-Verbose ("Search failed on {0}: {1}" -f $base, $_.Exception.Message)
    }
  }
  return $null, $basesTried
}

function List-AllZones {
  param([System.DirectoryServices.Protocols.LdapConnection]$Conn,[string]$DefaultNC)
  $bases = @(
    ("CN=MicrosoftDNS,DC=DomainDnsZones,{0}" -f $DefaultNC),
    ("CN=MicrosoftDNS,DC=ForestDnsZones,{0}" -f $DefaultNC),
    ("CN=MicrosoftDNS,CN=System,{0}" -f $DefaultNC)
  )
  foreach ($base in $bases) {
    Write-Host ("`n-- Zones under {0} --" -f $base) -ForegroundColor Yellow
    try {
      $req = [System.DirectoryServices.Protocols.SearchRequest]::new(
        $base,
        "(objectClass=dnsZone)",
        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        @("name","dc","distinguishedName")
      )
      $res = $Conn.SendRequest($req)
      if ($res.Entries.Count -eq 0) { Write-Detail "(none found)"; continue }
      foreach ($e in $res.Entries) {
        $n = $e.Attributes["name"]; if (-not $n) { $n = $e.Attributes["dc"] }
        $nStr = if ($n) { [string]$n[0] } else { "<unknown>" }
        Write-Detail ("{0}   ({1})" -f $nStr, $e.DistinguishedName)
      }
    } catch {
      Write-Detail ("Search failed: {0}" -f $_.Exception.Message)
    }
  }
}

if ($ListZones) {
  Write-Step "Enumerating AD-integrated DNS zones (read-only)"
  List-AllZones -Conn $conn -DefaultNC $defaultNC
  Write-OK "Finished listing zones. Exiting (no write test)."
  if ($LogPath) { try { Stop-Transcript | Out-Null } catch {} }
  return
}

Write-Step "Locating zone container"
$zoneDN,$tried = Get-ZoneDN -Conn $conn -ZoneFqdn $domainName -DefaultNC $defaultNC
if (-not $zoneDN) {
  Write-FAIL ("Zone '{0}' not found." -f $domainName)
  Write-Host "Bases tried:"
  $tried | ForEach-Object { Write-Detail ("- {0}" -f $_) }
  Write-Host "Hints:"
  Write-Detail "- Use -ListZones to enumerate what the DC actually stores."
  Write-Detail "- If your zone has a different FQDN, pass -Zone <fqdn>."
  Write-Detail "- Ensure the zone is AD-integrated (stored under MicrosoftDNS)."
  throw "Zone not located"
}
Write-OK ("Zone DN = {0}" -f $zoneDN)

#---------------------------
# Read zone SOA serial (dnsRecord on DC=@)
#---------------------------
function Get-ZoneSerial {
  param(
    [System.DirectoryServices.Protocols.LdapConnection]$Conn,
    [string]$ZoneDN
  )
  $rootNodeDn = ("DC=@,{0}" -f $ZoneDN)
  Write-Verbose ("Reading dnsRecord from {0}" -f $rootNodeDn)
  $req = [System.DirectoryServices.Protocols.SearchRequest]::new(
    $rootNodeDn,
    "(objectClass=dnsNode)",
    [System.DirectoryServices.Protocols.SearchScope]::Base,
    @("dnsRecord")
  )
  $res = $Conn.SendRequest($req)
  if ($res.Entries.Count -lt 1) { throw ("No dnsNode at {0}" -f $rootNodeDn) }
  $recs = $res.Entries[0].Attributes["dnsRecord"]
  if (-not $recs) { throw ("No dnsRecord values at {0}" -f $rootNodeDn) }
  $blob = [byte[]]$recs[0]
  if ($blob.Length -lt 12) { throw "dnsRecord too short to contain SOA Serial (need >= 12 bytes)" }

  # dnsRecord layout per MS-DNSP §2.3.2.2
  $serialLE = $blob[8..11]
  $serial = [BitConverter]::ToUInt32($serialLE,0)
  return $serial
}

Write-Step "Reading zone SOA serial"
$serial = Get-ZoneSerial -Conn $conn -ZoneDN $zoneDN
Write-OK ("SOA Serial = {0}" -f $serial)

#---------------------------
# Build dnsRecord (A) and attempt add
#---------------------------
function New-DnsRecordBlobA {
  param(
    [string]$IPv4,
    [uint32]$TtlSeconds,
    [uint32]$Serial
  )
  $bytes = New-Object System.Collections.Generic.List[byte]
  function Add-UInt16LE([UInt16]$v){ $bytes.AddRange([BitConverter]::GetBytes($v)) }
  function Add-UInt32LE([UInt32]$v){ $bytes.AddRange([BitConverter]::GetBytes($v)) }
  function Add-UInt32BE([UInt32]$v){ $b=[BitConverter]::GetBytes($v); [Array]::Reverse($b); $bytes.AddRange($b) }

  Add-UInt16LE 4            # DataLength
  Add-UInt16LE 1            # Type=A
  $bytes.Add(0x05)          # Version
  $bytes.Add(0x00)          # Rank
  Add-UInt16LE 0            # Flags
  Add-UInt32LE $Serial      # Serial (SOA)
  Add-UInt32BE $TtlSeconds  # TTL (big-endian)
  Add-UInt32LE 0            # Reserved
  Add-UInt32LE 0            # TimeStamp (0 = static)
  $ip = [System.Net.IPAddress]::Parse($IPv4)
  $bytes.AddRange($ip.GetAddressBytes())

  # RETURN A FLAT BYTE[]
  [byte[]]$out = $bytes.ToArray()
  return $out
}

Write-Step "Attempting low-priv DNS add via LDAP"
$label = ("_aclvtest-{0:x8}" -f (Get-Random))
$recordDN = ("DC={0},{1}" -f $label, $zoneDN)

# Build dnsRecord as raw byte[]
[byte[]]$dnsRecordBlob = New-DnsRecordBlobA -IPv4 $RecordIp -TtlSeconds 300 -Serial $serial

$created = $false
try {
  # Create an AddRequest and include required objectClass + RDN attribute (dc)
  $addReq = [System.DirectoryServices.Protocols.AddRequest]::new($recordDN)

  $oc = New-Object System.DirectoryServices.Protocols.DirectoryAttribute("objectClass")
  $null = $oc.Add("top")
  $null = $oc.Add("dnsNode")   # structural class
  $addReq.Attributes.Add($oc) | Out-Null

  # RDN attribute for dnsNode is Domain-Component => dc=<label>
  $addReq.Attributes.Add([System.DirectoryServices.Protocols.DirectoryAttribute]::new("dc", $label)) | Out-Null

  # name is commonly present on dnsNode; harmless to include
  $addReq.Attributes.Add([System.DirectoryServices.Protocols.DirectoryAttribute]::new("name", $label)) | Out-Null

  # IMPORTANT: dnsRecord as flat byte[]
  $addReq.Attributes.Add([System.DirectoryServices.Protocols.DirectoryAttribute]::new("dnsRecord", $dnsRecordBlob)) | Out-Null

  Write-Detail ("Adding '{0}.{1}' -> {2}" -f $label, $domainName, $RecordIp)
  $addRes = $conn.SendRequest($addReq)
  if ($addRes.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) {
    $created = $true
    Write-FAIL "VULNERABLE: low-priv add succeeded (record created)."
	$response = Read-Host "Feel free to verify. Hit a key and I will remove the entry"
  } else {
    Write-Detail ("LDAP returned: {0}" -f $addRes.ResultCode)
  }
} catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
  $rc = $_.Exception.Response.ResultCode
  $srv = $_.Exception.Response.ErrorMessage
  if ($rc -eq [System.DirectoryServices.Protocols.ResultCode]::InsufficientAccessRights) {
    Write-OK "PASS: Access denied on add (ACLs appear hardened)."
  } else {
    Write-FAIL ("LDAP error on add: {0}" -f $rc)
    if ($srv) { Write-Detail ("Server message: {0}" -f $srv) }
    throw
  }
} catch {
  Write-FAIL ("Unexpected error on add: {0}" -f $_.Exception.Message)
  throw
}

#---------------------------
# Cleanup
#---------------------------
if ($created -and -not $Keep) {
  Write-Step "Cleanup (delete test record)"
  try {
    $delReq = [System.DirectoryServices.Protocols.DeleteRequest]::new($recordDN)
    $conn.SendRequest($delReq) | Out-Null
    Write-OK ("Deleted test record {0}.{1}" -f $label, $domainName)
  } catch {
    Write-Warning ("Cleanup failed; remove manually in DNS or via dnscmd. DN: {0}" -f $recordDN)
  }
}

Write-Host "`n--- SUMMARY ---"
if ($created) {
  Write-FAIL ("Result: FAIL (low‑priv user could add DNS record in zone '{0}')." -f $domainName)
  Write-Host "Recommendation: Harden zone ACLs so low‑priv users cannot create records (per Depth Security)."
} else {
  Write-OK ("Result: PASS (low‑priv user could NOT add DNS record in zone '{0}')." -f $domainName)
}

if ($LogPath) { try { Stop-Transcript | Out-Null } catch {} }
