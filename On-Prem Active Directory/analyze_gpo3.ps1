<#
.SYNOPSIS
  Scans applied GPOs from a GPResult XML, reports SYSVOL contents,
  then runs Get-GPOReport and parses extra XML nodes.

.PARAMETER GPResultXml
  Path to your exported GPResult XML.

.PARAMETER SysvolRoot
  UNC path to \\<DC>\SYSVOL\<domain>\Policies
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateScript({ Test-Path $_ -PathType Leaf })]  [string]$GPResultXml,
  [Parameter(Mandatory)][ValidateScript({ Test-Path $_ -PathType Container })][string]$SysvolRoot
)

$VerbosePreference = 'Continue'
$SysvolRoot = $SysvolRoot.TrimEnd('\')

# Load GroupPolicy module if needed
$canGetGpo = (Get-Command Get-GPO -ErrorAction SilentlyContinue)
if (-not $canGetGpo) {
  Import-Module GroupPolicy -SkipEditionCheck -ErrorAction SilentlyContinue
  $canGetGpo = (Get-Command Get-GPO -ErrorAction SilentlyContinue)
}

function Get-AppliedGpoGuids {
  [CmdletBinding()] param([string]$XmlPath)

  Write-Verbose "Loading XML from '$XmlPath'..."
  try {
    [xml]$doc = Get-Content -Path $XmlPath -ErrorAction Stop
  } catch {
    Write-Error ("Failed to load XML: {0}" -f $_)
    return @()
  }

  # Grab <Id> and <Identifier>, namespace-agnostic
  $nodes = @()
  $nodes += $doc.SelectNodes("//*[local-name()='Id']")
  $nodes += $doc.SelectNodes("//*[local-name()='Identifier']")

  if (-not $nodes -or $nodes.Count -eq 0) {
    Write-Warning "No <Id> or <Identifier> elements found."
    return @()
  }

  Write-Verbose "Found $($nodes.Count) raw GUID node(s)."
  $nodes |
    ForEach-Object {
      $raw   = $_.InnerText.Trim()
      Write-Verbose ("  Raw GUID:    {0}" -f $raw)
      $clean = $raw.Trim('{}').Trim().ToUpperInvariant()
      Write-Verbose ("  Clean GUID:  {0}" -f $clean)
      $clean
    } |
    Sort-Object -Unique
}

function Analyze-GpoFolder {
  [CmdletBinding()]
  param(
    [string]$Root,
    [string]$GpoId
  )

  # Build folder name (with braces)
  if ($GpoId -match '^\{.+\}$') {
    $folderName = $GpoId
  } else {
    $folderName = "{${GpoId}}"
  }
  $path = Join-Path -Path $Root -ChildPath $folderName
  Write-Verbose ("Checking SYSVOL path: {0}" -f $path)

  if (-not (Test-Path -Path $path)) {
    Write-Verbose ("  Not found")
    return @{
      GPOID             = $GpoId; Found             = 'No'
      RegistryPolicy    = 'N/A'; SoftwareInstall   = 'N/A'
      ScriptDeployments = 'N/A'; Preferences       = 'N/A'
      MSIFiles          = '';    ScriptFiles       = ''
      PreferenceFiles   = ''
    }
  }

  Write-Verbose ("  Folder found")
  $hasReg   = Test-Path (Join-Path $path 'Machine\registry.pol')
  $msiObjs  = Get-ChildItem `
                -Path (Join-Path $path 'Machine\Microsoft\Windows\Group Policy\Software Installation') `
                -Filter '*.xml' -Recurse -File -ErrorAction SilentlyContinue
  $scrObjs  = Get-ChildItem `
                -Path (Join-Path $path 'Machine\Scripts\Startup'), (Join-Path $path 'User\Scripts\Logon') `
                -Include '*.ps1','*.cmd','*.bat' -Recurse -File -ErrorAction SilentlyContinue
  $prefObjs = Get-ChildItem `
                -Path (Join-Path $path 'Machine\Preferences'), (Join-Path $path 'User\Preferences') `
                -Filter '*.xml' -Recurse -File -ErrorAction SilentlyContinue

  return @{
    GPOID             = $GpoId
    Found             = 'Yes'
    RegistryPolicy    = if ($hasReg)  {'Yes'} else {'No'}
    SoftwareInstall   = if ($msiObjs) {'Yes'} else {'No'}
    ScriptDeployments = if ($scrObjs) {'Yes'} else {'No'}
    Preferences       = if ($prefObjs){'Yes'} else {'No'}
    MSIFiles          = $msiObjs.FullName      -join ';'
    ScriptFiles       = $scrObjs.FullName      -join ';'
    PreferenceFiles   = $prefObjs.FullName     -join ';'
  }
}

function Get-FriendlyGpoName {
  param([string]$GpoId)
  if ($canGetGpo) {
    try { (Get-GPO -Id $GpoId -ErrorAction Stop).DisplayName } catch { '' }
  }
}

# === Main ===
$guids = Get-AppliedGpoGuids -XmlPath $GPResultXml
if ($guids.Count -eq 0) {
  Write-Error "No applied GPO GUIDs detected."
  exit 1
}
Write-Verbose "Applied GUIDs:`n  $($guids -join "`n  ")"

$report = foreach ($Gpo in $guids) {
  # Folder scan
  $stats = Analyze-GpoFolder -Root $SysvolRoot -GpoId $Gpo

  # Prepare containers
  $srcNames=@(); $scriptNames=@(); $prefExt=@()
  $regKeys=@(); $regVals=@(); $msiPkgNames=@()

  if ($canGetGpo) {
    $tmp = [IO.Path]::GetTempFileName()
    Write-Verbose ("Generating Get-GPOReport for {0}" -f $Gpo)
    try {
      Get-GPOReport -Id $Gpo -ReportType Xml -Path $tmp -ErrorAction Stop
      [xml]$xml = Get-Content $tmp
      Remove-Item $tmp -ErrorAction SilentlyContinue

      # Pull full XML nodes
      $srcNames    = $xml.SelectNodes("//*[local-name()='SourceName']")     | ForEach-Object { $_.InnerText.Trim() }
      $scriptNames = $xml.SelectNodes("//*[local-name()='ScriptName']")     | ForEach-Object { $_.InnerText.Trim() }
      $prefExt     = $xml.SelectNodes("//*[local-name()='ExtensionName']")  | ForEach-Object { $_.InnerText.Trim() }
      $regKeys     = $xml.SelectNodes("//*[local-name()='KeyName']")        | ForEach-Object { $_.InnerText.Trim() }
      $regVals     = $xml.SelectNodes("//*[local-name()='ValueName']")      | ForEach-Object { $_.InnerText.Trim() }
      $msiPkgNames = $xml.SelectNodes("//*[local-name()='MSIPackage']/*[local-name()='Name']") | ForEach-Object { $_.InnerText.Trim() }
    }
    catch {
      Write-Warning ("Get-GPOReport failed for {0}: {1}" -f $Gpo, $_)
    }
  }

  # Build full paths for MSI & scripts
  $msiPaths    = $srcNames | ForEach-Object {
                    Join-Path $SysvolRoot "{{$Gpo}}\Machine\Microsoft\Windows\Group Policy\Software Installation\$_"
                  }
  $scriptPaths = $scriptNames | ForEach-Object {
                    $p1 = Join-Path $SysvolRoot "{{$Gpo}}\Machine\Scripts\Startup\$_"
                    $p2 = Join-Path $SysvolRoot "{{$Gpo}}\User\Scripts\Logon\$_"
                    if (Test-Path $p1) { $p1 } elseif (Test-Path $p2) { $p2 } else { $_ }
                  }

  [PSCustomObject]@{
    DisplayName             = Get-FriendlyGpoName -GpoId $Gpo
    GPOID                   = $stats.GPOID
    Found                   = $stats.Found
    RegistryPolicy          = $stats.RegistryPolicy
    SoftwareInstall         = $stats.SoftwareInstall
    ScriptDeployments       = $stats.ScriptDeployments
    Preferences             = $stats.Preferences
    MSIFiles                = $stats.MSIFiles
    ScriptFiles             = $stats.ScriptFiles
    PreferenceFiles         = $stats.PreferenceFiles

    ReportedMsiSources      = $srcNames         -join ';'
    ReportedMsiPackageNames = $msiPkgNames      -join ';'
    ReportedScripts         = $scriptNames      -join ';'
    ReportedPrefExts        = $prefExt          -join ';'
    ReportedRegistryKeys    = $regKeys          -join ';'
    ReportedRegistryValues  = $regVals          -join ';'

    FullMsiPaths            = $msiPaths         -join ';'
    FullScriptPaths         = $scriptPaths      -join ';'
  }
}

# Show every property
$report |
  Sort-Object Found, DisplayName |
  Format-List *