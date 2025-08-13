<#
.SYNOPSIS
  Audit powerful rights over GPOs and enrich with principal identity and GPO details.

.DESCRIPTION
  - Targets groupPolicyContainer objects in the specified domain.
  - Filters ACLs to non-default SIDs (RID >= 1000) with high-impact rights
    (WriteProperty, GenericWrite, GenericAll, WriteDacl, WriteOwner).
  - Resolves each SID to detailed identity info (User/Group/Computer).
  - Adds GPO metadata (DisplayName, Status, Creation/Modification times).
  - Prints disabled/inactive principals in RED.

.PARAMETER DomainName
  FQDN of the AD domain to query (e.g., xxx.net).

.REQUIREMENTS
  - PowerView: Get-DomainObjectAcl (and optionally Convert-ADName).
  - ActiveDirectory module (Get-ADUser/Group/Computer).
  - GroupPolicy module (Get-GPO) for friendly GPO details.

#>

[CmdletBinding()]
param(
  [string]$DomainName = 'xxx.net'
)

# --- Helpers ---------------------------------------------------------------

function Test-Command { param([string]$Name) [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue) }

$haveAD  = Test-Command -Name Get-ADUser
$haveGPO = Test-Command -Name Get-GPO

if (-not (Test-Command -Name Get-DomainObjectAcl)) {
  Write-Error "Get-DomainObjectAcl not found. Import PowerView (PowerView.ps1) and re-run."
  return
}

if (-not $haveAD) {
  Write-Warning "ActiveDirectory module not found. Identity enrichment will be limited."
}
if (-not $haveGPO) {
  Write-Warning "GroupPolicy module not found. GPO names/details will be limited to GUID."
}

function Get-DomainNetBIOSName {
  if ($haveAD) { try { (Get-ADDomain -Server $DomainName).NetBIOSName } catch { $null } }
}
$netbios = Get-DomainNetBIOSName

# Cache lookups to speed things up
$principalCache = @{}  # SID -> resolved object
$gpoCache       = @{}  # GUID -> metadata object

function Resolve-Principal {
  param([string]$Sid)

  if ($principalCache.ContainsKey($Sid)) { return $principalCache[$Sid] }

  $u = $g = $c = $null
  if ($haveAD) {
    try { $u = Get-ADUser -Identity $Sid -Properties DisplayName,UserPrincipalName,LastLogonDate,whenCreated,Enabled,AccountExpirationDate,LockedOut,PasswordLastSet,MemberOf -ErrorAction Stop } catch {}
    if (-not $u) { try { $g = Get-ADGroup -Identity $Sid -Properties whenCreated,MemberOf -ErrorAction Stop } catch {} }
    if (-not $u -and -not $g) { try { $c = Get-ADComputer -Identity $Sid -Properties whenCreated,Enabled,LastLogonDate,PasswordLastSet,MemberOf -ErrorAction Stop } catch {} }
  }

  $principalType   = $null
  $principalDN     = $null
  $sam             = $null
  $upn             = $null
  $display         = $null
  $enabled         = $null
  $acctExpireDate  = $null
  $isActive        = $null
  $lockedOut       = $null
  $lastLogon       = $null
  $pwdLastSet      = $null
  $firstSeenApprox = $null
  $groups          = $null
  $domainSam       = $null

  if ($u) {
    $principalType   = 'User'
    $principalDN     = $u.DistinguishedName
    $sam             = $u.SamAccountName
    $upn             = $u.UserPrincipalName
    $display         = $u.DisplayName
    $enabled         = $u.Enabled
    $acctExpireDate  = $u.AccountExpirationDate
    $lockedOut       = $u.LockedOut
    $lastLogon       = $u.LastLogonDate
    $pwdLastSet      = $u.PasswordLastSet
    $firstSeenApprox = $u.whenCreated
    try {
      $groups = ($u.MemberOf | ForEach-Object { (Get-ADGroup $_ -ErrorAction SilentlyContinue).SamAccountName }) -join ', '
    } catch { $groups = $null }
    if ($sam -and $netbios) { $domainSam = "$netbios\$sam" }
    if ($enabled -ne $null) {
      $isActive = if (-not $acctExpireDate) { $enabled } else { $enabled -and ($acctExpireDate -gt (Get-Date)) }
    }
  }
  elseif ($g) {
    $principalType   = 'Group'
    $principalDN     = $g.DistinguishedName
    $sam             = $g.SamAccountName
    $display         = $g.Name
    $firstSeenApprox = $g.whenCreated
    try {
      $groups = ($g.MemberOf | ForEach-Object { (Get-ADGroup $_ -ErrorAction SilentlyContinue).SamAccountName }) -join ', '
    } catch { $groups = $null }
    if ($sam -and $netbios) { $domainSam = "$netbios\$sam" }
  }
  elseif ($c) {
    $principalType   = 'Computer'
    $principalDN     = $c.DistinguishedName
    $sam             = $c.SamAccountName
    $enabled         = $c.Enabled
    $lastLogon       = $c.LastLogonDate
    $pwdLastSet      = $c.PasswordLastSet
    $firstSeenApprox = $c.whenCreated
    try {
      $groups = ($c.MemberOf | ForEach-Object { (Get-ADGroup $_ -ErrorAction SilentlyContinue).SamAccountName }) -join ', '
    } catch { $groups = $null }
    if ($sam -and $netbios) { $domainSam = "$netbios\$sam" }
    if ($enabled -ne $null) { $isActive = $enabled }
  }
  else {
    # Fallback: try to get DN via Convert-ADName if available
    $principalDN = $null
    if (Test-Command -Name Convert-ADName) {
      try { $principalDN = Convert-ADName $Sid -OutputType DN -ErrorAction Stop } catch {}
    }
  }

  $obj = [PSCustomObject]@{
    PrincipalSID     = $Sid
    PrincipalDN      = $principalDN
    PrincipalType    = $principalType
    PrincipalAccount = $domainSam
    SamAccountName   = $sam
    UserPrincipal    = $upn
    DisplayName      = $display
    Enabled          = $enabled
    AccountExpires   = $acctExpireDate
    IsActive         = $isActive
    LockedOut        = $lockedOut
    LastLogon        = $lastLogon
    PasswordLastSet  = $pwdLastSet
    FirstSeenApprox  = $firstSeenApprox
    Groups           = $groups
  }

  $principalCache[$Sid] = $obj
  return $obj
}

function Get-GpoDetails {
  param([string]$GuidText)

  if ([string]::IsNullOrWhiteSpace($GuidText)) { return $null }
  $key = $GuidText.ToLowerInvariant()
  if ($gpoCache.ContainsKey($key)) { return $gpoCache[$key] }

  $meta = $null
  if ($haveGPO) {
    try {
      $g = Get-GPO -Guid $GuidText -Domain $DomainName -ErrorAction Stop
      $meta = [PSCustomObject]@{
        GPOName          = $g.DisplayName
        GPOGuid          = $g.Id.Guid
        GPOStatus        = $g.GpoStatus
        GPOCreationTime  = $g.CreationTime
        GPOModifiedTime  = $g.ModificationTime
      }
    } catch {
      $meta = [PSCustomObject]@{
        GPOName          = $null
        GPOGuid          = $GuidText
        GPOStatus        = $null
        GPOCreationTime  = $null
        GPOModifiedTime  = $null
      }
    }
  } else {
    $meta = [PSCustomObject]@{
      GPOName          = $null
      GPOGuid          = $GuidText
      GPOStatus        = $null
      GPOCreationTime  = $null
      GPOModifiedTime  = $null
    }
  }

  $gpoCache[$key] = $meta
  return $meta
}

function Write-RecordColored {
  param([pscustomobject]$Record)

  $isDormant = ($Record.Enabled -eq $false) -or ($Record.IsActive -eq $false)
  $sel = $Record | Select-Object `
    GPOName,GPOGuid,ObjectDN,PrincipalType,PrincipalAccount,SamAccountName,UserPrincipal,DisplayName,Enabled,IsActive,LockedOut,LastLogon,PasswordLastSet,FirstSeenApprox,Groups,PrincipalDN,PrincipalSID

  if ($isDormant) {
    Write-Host ($sel | Format-List | Out-String) -ForegroundColor Red
  } else {
    $sel | Format-List
  }
}

# --- Query and output ------------------------------------------------------

$acls = Get-DomainObjectAcl -Domain $DomainName -LDAPFilter '(objectCategory=groupPolicyContainer)' -ResolveGUIDs

$filtered = $acls | Where-Object {
  ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and
  ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')
}

if (-not $filtered) {
  Write-Host "[*] No matching ACEs found." -ForegroundColor Yellow
  return
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($ace in $filtered) {
  $objDN = $ace.ObjectDN

  # Extract GPO GUID from ObjectDN: CN={GUID},CN=Policies,...
  $gpoGuid = $null
  if ($objDN -match 'CN=\{([0-9A-Fa-f-]+)\},CN=Policies') { $gpoGuid = $matches[1].ToUpper() }

  $gpoInfo = Get-GpoDetails -GuidText $gpoGuid
  $principal = Resolve-Principal -Sid $ace.SecurityIdentifier

  $row = [PSCustomObject]@{
    GPOName          = $gpoInfo.GPOName
    GPOGuid          = $gpoInfo.GPOGuid
    ObjectDN         = $objDN

    PrincipalSID     = $principal.PrincipalSID
    PrincipalDN      = $principal.PrincipalDN
    PrincipalType    = $principal.PrincipalType
    PrincipalAccount = $principal.PrincipalAccount
    SamAccountName   = $principal.SamAccountName
    UserPrincipal    = $principal.UserPrincipal
    DisplayName      = $principal.DisplayName
    Enabled          = $principal.Enabled
    AccountExpires   = $principal.AccountExpires
    IsActive         = $principal.IsActive
    LockedOut        = $principal.LockedOut
    LastLogon        = $principal.LastLogon
    PasswordLastSet  = $principal.PasswordLastSet
    FirstSeenApprox  = $principal.FirstSeenApprox
    Groups           = $principal.Groups
  }

  $results.Add($row) | Out-Null
}

foreach ($r in $results) { Write-RecordColored -Record $r }