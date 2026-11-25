#requires -Version 7.0
<#
.SYNOPSIS
  Performs private, local, first-line PDF triage on every file in a folder.
.DESCRIPTION
  PeeDeeEff v1.5.1 is a PowerShell 7-only PDF triage utility. It does not upload
  or execute document content. It uses qpdf JSON v2 for object-aware action
  analysis, records encryption and permissions, validates embedded Windows PE
  structure, identifies duplicates, and exports CSV/JSON evidence.

  Non-PDF files are recorded as NOT A PDF without invoking qpdf. Files carrying
  a .pdf extension without PDF content are rejected. Recognized Adobe form-field
  JavaScript is separated from unknown JavaScript. Launch targets are extracted
  when qpdf exposes them.

  A PASS means no selected indicator was detected. It is not proof of safety.
.VERSION
  1.5.1
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory, Position=0)]
  [ValidateNotNullOrEmpty()]
  [string]$Path,

  [switch]$Recurse,

  [ValidateRange(1,2048)]
  [int]$MaxReadMB = 512,

  [ValidateRange(128,8192)]
  [int]$EvidenceLength = 1000,

  [switch]$RunSelfTest,

  [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.5.1'

function Write-Banner {
  $banner = @'
  ____             ____             _____  __  __
 |  _ \ ___  ___  |  _ \  ___  ___| ____|/ _|/ _|
 | |_) / _ \/ _ \ | | | |/ _ \/ _ \  _| | |_| |_
 |  __/  __/  __/ | |_| |  __/  __/ |___|  _|  _|
 |_|   \___|\___| |____/ \___|\___|_____|_| |_|

      P e e D e e E f f   Local PDF Triage
'@
  Write-Host $banner -ForegroundColor Cyan
  Write-Host "Version $ScriptVersion | PowerShell 7+ | qpdf JSON v2 | Local-only" -ForegroundColor DarkCyan
  Write-Host ('=' * 96) -ForegroundColor DarkGray
}

function Write-Status {
  param(
    [ValidateSet('INFO','PASS','WARN','FAIL','SKIP')][string]$Level,
    [string]$Message
  )
  $color = @{ INFO='Cyan'; PASS='Green'; WARN='Yellow'; FAIL='Red'; SKIP='DarkGray' }[$Level]
  Write-Host ("[{0,-4}] {1}" -f $Level,$Message) -ForegroundColor $color
}

function Invoke-CommandCapture {
  param([string]$Executable,[string[]]$Arguments)
  $output = & $Executable @Arguments 2>&1
  $exitCode = $LASTEXITCODE
  [pscustomobject]@{
    ExitCode = $exitCode
    Text = (($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
  }
}

function Get-PdfHeaderOffset {
  param([string]$FilePath)
  $stream = [IO.File]::Open($FilePath,'Open','Read','ReadWrite')
  try {
    $length = [Math]::Min(1024L,$stream.Length)
    $bytes = [byte[]]::new([int]$length)
    $count = $stream.Read($bytes,0,$bytes.Length)
    $needle = [Text.Encoding]::ASCII.GetBytes('%PDF-')
    for ($i=0; $i -le $count-$needle.Length; $i++) {
      $match = $true
      for ($j=0; $j -lt $needle.Length; $j++) {
        if ($bytes[$i+$j] -ne $needle[$j]) { $match=$false; break }
      }
      if ($match) { return $i }
    }
    return -1
  }
  finally { $stream.Dispose() }
}

function Get-QpdfWarnings {
  param([string]$Output,[int]$ExitCode)
  $warnings = @(
    ($Output -split '\r?\n') |
      Where-Object { $_ -match '(?i)^WARNING:' } |
      ForEach-Object { ($_ -replace '(?i)^WARNING:\s*','').Trim() }
  )
  if ($ExitCode -notin 0,3) { $class='Fatal' }
  elseif ($warnings.Count -eq 0) { $class='None' }
  else {
    $classes = foreach ($warning in $warnings) {
      if ($warning -match '(?i)input stream is complete but output may still be valid|recoverable') { 'RecoverableStreamWarning' }
      elseif ($warning -match '(?i)damaged|reconstruct|xref|cross-reference|linearized|hint table|object count mismatch|shared object') { 'ReconstructedStructure' }
      elseif ($warning -match '(?i)password') { 'PasswordRelated' }
      else { 'OtherWarning' }
    }
    $class = (@($classes | Select-Object -Unique) -join ',')
  }
  [pscustomobject]@{ Class=$class; Count=$warnings.Count; Summary=($warnings -join ' | ') }
}

function Get-QpdfPermissions {
  param([string]$Text)
  $labels=[ordered]@{
    AccessibilityExtract='extract for accessibility'; GeneralExtract='extract for any purpose'
    PrintLowResolution='print low resolution'; PrintHighResolution='print high resolution'
    ModifyAssembly='modify document assembly'; ModifyForms='modify forms'
    ModifyAnnotations='modify annotations'; ModifyOther='modify other'; ModifyAnything='modify anything'
  }
  $pairs = foreach ($key in $labels.Keys) {
    $m=[regex]::Match($Text,'(?im)^'+[regex]::Escape($labels[$key])+':\s*(?<v>.+?)\s*$')
    "$key=$(if($m.Success){$m.Groups['v'].Value.Trim()}else{'Unknown'})"
  }
  $pairs -join '; '
}

function Get-ObjectMap {
  param([object]$Root)
  $map=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
  function Visit([object]$Node) {
    if ($null -eq $Node) { return }
    if ($Node -is [Collections.IDictionary]) {
      foreach ($key in @($Node.Keys)) {
        $name=[string]$key
        if ($name -match '^obj:(?<ref>\d+\s+\d+\s+R)$') { $map[$Matches.ref]=$Node[$key] }
        Visit $Node[$key]
      }
    }
    elseif ($Node -is [Collections.IEnumerable] -and $Node -isnot [string]) {
      foreach ($item in $Node) { Visit $item }
    }
  }
  Visit $Root
  return $map
}

function ConvertTo-Evidence {
  param([object]$Value,[int]$Length)
  if ($null -eq $Value) { return '' }
  $text = ConvertTo-Json $Value -Compress -Depth 50
  $text = ($text -replace '[\x00-\x1F]','?' -replace '\s+',' ').Trim()
  if ($text.Length -gt $Length) { return $text.Substring(0,$Length)+'...' }
  return $text
}

function Get-HashtableValue {
  param([object]$Node,[string[]]$Names)
  if ($Node -isnot [Collections.IDictionary]) { return $null }
  foreach ($name in $Names) {
    foreach ($candidate in @($name,"/$name")) {
      if ($Node.Contains($candidate)) { return $Node[$candidate] }
    }
  }
  return $null
}

function Find-FirstKeyValue {
  param([object]$Node,[string[]]$Names)
  if ($null -eq $Node) { return $null }
  if ($Node -is [Collections.IDictionary]) {
    $direct = Get-HashtableValue -Node $Node -Names $Names
    if ($null -ne $direct) { return $direct }
    foreach ($key in @($Node.Keys)) {
      $found = Find-FirstKeyValue -Node $Node[$key] -Names $Names
      if ($null -ne $found) { return $found }
    }
  }
  elseif ($Node -is [Collections.IEnumerable] -and $Node -isnot [string]) {
    foreach ($item in $Node) {
      $found = Find-FirstKeyValue -Node $item -Names $Names
      if ($null -ne $found) { return $found }
    }
  }
  return $null
}

function Get-JavaScriptClassification {
  param([string]$Evidence)
  $script = $Evidence
  if ($script -match '(?i)AFDate_KeystrokeEx\s*\(\s*(?:\\?["''])yyyy(?:\\?["''])\s*\)') {
    return 'RecognizedAdobeFormDateValidation'
  }
  if ($script -match '(?i)\b(app\.launchURL|this\.submitForm|this\.getURL|Net\.|SOAP\.|util\.readFileIntoStream|this\.importDataObject|this\.exportDataObject|app\.openDoc|app\.execMenuItem|eval\s*\(|Function\s*\()') {
    return 'HighRiskJavaScriptPrimitive'
  }
  return 'UnclassifiedJavaScript'
}

function Get-PdfActions {
  param([Collections.Generic.Dictionary[string,object]]$ObjectMap,[int]$EvidenceLength)
  $actions=[Collections.Generic.List[object]]::new()
  foreach ($reference in @($ObjectMap.Keys | Sort-Object)) {
    $node=$ObjectMap[$reference]
    $json=ConvertTo-Json $node -Compress -Depth 50
    $type=$null
    foreach ($candidate in 'JavaScript','Launch','SubmitForm','GoToR','GoToE','URI','Named') {
      if ($json -match ('(?i)"/?S"\s*:\s*"/'+[regex]::Escape($candidate)+'"')) { $type=$candidate; break }
    }
    if (-not $type) { continue }

    $evidence=ConvertTo-Evidence $node $EvidenceLength
    $target=''
    $classification=''
    if ($type -eq 'JavaScript') {
      # Classify the actual /JS value rather than serialized JSON evidence. JSON
      # escaping changes embedded quotes to backslash-quote and caused v1.5.0's
      # recognized Adobe form JavaScript regression test to fail.
      $scriptValue=Find-FirstKeyValue -Node $node -Names @('JS')
      $scriptText=if($null -ne $scriptValue){ConvertTo-Evidence $scriptValue $EvidenceLength}else{$evidence}
      $classification=Get-JavaScriptClassification $scriptText
    }
    elseif ($type -eq 'Launch') {
      $targetValue=Find-FirstKeyValue -Node $node -Names @('F','File','Win','Unix','Mac')
      if ($null -ne $targetValue) { $target=ConvertTo-Evidence $targetValue $EvidenceLength }
      if (-not $target) { $target='Unresolved' }
    }
    elseif ($type -eq 'URI') {
      $targetValue=Find-FirstKeyValue -Node $node -Names @('URI')
      if ($null -ne $targetValue) { $target=ConvertTo-Evidence $targetValue $EvidenceLength }
    }

    $actions.Add([pscustomobject]@{
      ObjectReference=$reference; ActionType=$type; Classification=$classification
      Target=$target; Evidence=$evidence
    })
  }
  return $actions.ToArray()
}

function Find-ValidPE {
  param([string]$FilePath,[long]$MaximumBytes)
  $stream=[IO.File]::Open($FilePath,'Open','Read','ReadWrite')
  try {
    $length=[Math]::Min($stream.Length,[Math]::Min($MaximumBytes,[int]::MaxValue))
    $data=[byte[]]::new([int]$length);$total=0
    while($total -lt $data.Length){$n=$stream.Read($data,$total,$data.Length-$total);if($n -eq 0){break};$total+=$n}
    $hits=[Collections.Generic.List[object]]::new()
    for($offset=0;$offset -le $total-64;$offset++){
      if($data[$offset]-ne 0x4D -or $data[$offset+1]-ne 0x5A){continue}
      $peOffset=[BitConverter]::ToUInt32($data,$offset+0x3C);$pe=[long]$offset+$peOffset
      if($peOffset-lt 0x40 -or $peOffset-gt 0x10000000 -or $pe+24-gt $total){continue}
      if($data[$pe]-ne 0x50 -or $data[$pe+1]-ne 0x45 -or $data[$pe+2]-ne 0 -or $data[$pe+3]-ne 0){continue}
      $machine=[BitConverter]::ToUInt16($data,[int]$pe+4);$sections=[BitConverter]::ToUInt16($data,[int]$pe+6);$opt=[BitConverter]::ToUInt16($data,[int]$pe+20)
      if($machine -in 0x014c,0x8664,0x01c0,0x01c4,0xAA64 -and $sections -ge 1 -and $sections -le 96 -and $opt -le 4096){$hits.Add([pscustomobject]@{Offset=$offset;PEOffset=$peOffset;Machine=('0x{0:X4}'-f $machine);Sections=$sections})}
    }
    return $hits.ToArray()
  }
  finally {$stream.Dispose()}
}

function Invoke-QpdfAnalysis {
  param([string]$FilePath,[string]$TempPath,[long]$MaximumBytes,[int]$EvidenceLength)
  $qpdf=(Get-Command qpdf -ErrorAction Stop).Source
  $version=(Invoke-CommandCapture $qpdf @('--version')).Text.Split([Environment]::NewLine)[0]
  $check=Invoke-CommandCapture $qpdf @('--check','--',$FilePath)
  $warning=Get-QpdfWarnings $check.Text $check.ExitCode
  $enc=Invoke-CommandCapture $qpdf @('--show-encryption','--',$FilePath)
  $isEncrypted=$enc.Text -notmatch '(?im)^File is not encrypted\s*$'
  $user=[regex]::Match($enc.Text,'(?im)^User password =(?<v>.*)$')
  $empty=$isEncrypted -and $user.Success -and [string]::IsNullOrWhiteSpace($user.Groups['v'].Value) -and $enc.Text -match '(?im)^Supplied password is user password\s*$'
  $permissionOnly=$empty -and $enc.ExitCode -eq 0
  $revision=[regex]::Match($enc.Text,'(?im)^R\s*=\s*(?<v>\d+)\s*$')

  $jsonFile=Join-Path $TempPath (([guid]::NewGuid().ToString('N'))+'.json')
  $normalized=Join-Path $TempPath (([guid]::NewGuid().ToString('N'))+'.pdf')
  try {
    $jsonCall=Invoke-CommandCapture $qpdf @('--json=2','--json-stream-data=none','--json-output',$FilePath,$jsonFile)
    $jsonComplete=$jsonCall.ExitCode -in 0,3 -and (Test-Path -LiteralPath $jsonFile -PathType Leaf)
    $jsonError='';$objectCount=0;$actions=@()
    if($jsonComplete){
      try {
        $doc=Get-Content -LiteralPath $jsonFile -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable -Depth 100
        $map=Get-ObjectMap $doc;$objectCount=$map.Count;$actions=@(Get-PdfActions $map $EvidenceLength)
      }
      catch {$jsonComplete=$false;$jsonError=$_.Exception.Message}
    }
    else {$jsonError="qpdf JSON exit $($jsonCall.ExitCode): $($jsonCall.Text)"}

    $normalizeCall=Invoke-CommandCapture $qpdf @('--decrypt','--object-streams=disable','--stream-data=uncompress','--',$FilePath,$normalized)
    $normalizedOK=$normalizeCall.ExitCode -in 0,3 -and (Test-Path -LiteralPath $normalized -PathType Leaf)
    $pe=@();if($normalizedOK){$pe=@(Find-ValidPE $normalized $MaximumBytes)}

    $js=@($actions|Where-Object ActionType -eq 'JavaScript')
    $knownJs=@($js|Where-Object Classification -eq 'RecognizedAdobeFormDateValidation')
    $highRiskJs=@($js|Where-Object Classification -eq 'HighRiskJavaScriptPrimitive')
    $unknownJs=@($js|Where-Object Classification -eq 'UnclassifiedJavaScript')
    $launch=@($actions|Where-Object ActionType -eq 'Launch')
    $submit=@($actions|Where-Object ActionType -eq 'SubmitForm')
    $remote=@($actions|Where-Object ActionType -in 'GoToR','GoToE')
    $uri=@($actions|Where-Object ActionType -eq 'URI')
    $named=@($actions|Where-Object ActionType -eq 'Named')

    $joinObjects = { param($items) if($items.Count){($items|ForEach-Object{$_.ObjectReference})-join', '}else{''} }
    $joinEvidence = { param($items) if($items.Count){($items|ForEach-Object{"Object $($_.ObjectReference): $($_.Evidence)"})-join' | '}else{''} }
    $launchTargets = if($launch.Count){($launch|ForEach-Object{"Object $($_.ObjectReference): $($_.Target)"})-join' | '}else{''}
    $summary = if($actions.Count){($actions|ForEach-Object{"$($_.ActionType):$($_.ObjectReference)$(if($_.Target){' Target='+$_.Target}else{''})"})-join'; '}else{''}

    [pscustomobject]@{
      Version=$version;CheckExitCode=$check.ExitCode;CheckOutput=$check.Text;WarningClass=$warning.Class;WarningCount=$warning.Count;WarningSummary=$warning.Summary
      IsEncrypted=$isEncrypted;EmptyUserPassword=$empty;PermissionOnlyEncryption=$permissionOnly;EncryptionRevision=$(if($revision.Success){$revision.Groups['v'].Value}else{''});Permissions=(Get-QpdfPermissions $enc.Text)
      JsonCompleted=$jsonComplete;JsonError=$jsonError;JsonObjectCount=$objectCount
      JavaScriptCount=$js.Count;RecognizedAdobeJavaScriptCount=$knownJs.Count;HighRiskJavaScriptCount=$highRiskJs.Count;UnclassifiedJavaScriptCount=$unknownJs.Count
      JavaScriptObjects=(& $joinObjects $js);JavaScriptEvidence=(& $joinEvidence $js)
      LaunchCount=$launch.Count;LaunchObjects=(& $joinObjects $launch);LaunchTargets=$launchTargets
      SubmitFormCount=$submit.Count;RemoteActionCount=$remote.Count;UriActionCount=$uri.Count;NamedActionCount=$named.Count;ActionSummary=$summary
      NormalizationCompleted=$normalizedOK;PECount=$pe.Count;PEDetails=(($pe|ForEach-Object{"Offset=$($_.Offset),PEOffset=$($_.PEOffset),Machine=$($_.Machine),Sections=$($_.Sections)"})-join' | ')
    }
  }
  finally {Remove-Item -LiteralPath $jsonFile,$normalized -Force -ErrorAction SilentlyContinue}
}

function New-ResultRecord {
  param([IO.FileInfo]$File)
  [ordered]@{
    FileName=$File.Name;FullPath=$File.FullName;Extension=$File.Extension;SizeBytes=$File.Length;LastWriteTimeUtc=$File.LastWriteTimeUtc.ToString('o');SHA256='';DuplicateGroupSize=1
    IsPdf=$false;PdfHeaderOffset=-1;ExtensionMatchesContent=$false;AnalysisComplete=$false
    QpdfVersion='';QpdfExitCode=$null;QpdfWarningClass='';QpdfWarningCount=0;QpdfWarningSummary='';QpdfCheckOutput='';QpdfJsonCompleted=$false;QpdfJsonError='';QpdfObjectCount=0
    IsEncrypted=$false;EmptyUserPassword=$false;PermissionOnlyEncryption=$false;PasswordLikelyRequired='Unknown';EncryptionRevision='';QpdfPermissions=''
    JavaScriptActionCount=0;RecognizedAdobeJavaScriptCount=0;HighRiskJavaScriptCount=0;UnclassifiedJavaScriptCount=0;JavaScriptObjects='';JavaScriptEvidence=''
    LaunchActionCount=0;LaunchObjects='';LaunchTargets='';SubmitFormActionCount=0;RemoteActionCount=0;UriActionCount=0;NamedActionCount=0;ActionSummary=''
    NormalizationCompleted=$false;ConfirmedPortableExecutable=$false;ConfirmedPECount=0;PEDetails=''
    Risk='';Disposition='';Findings='';Informational='';Errors=''
  }
}

function Invoke-SelfTest {
  Write-Status INFO 'Running regression self-tests.'
  $json='{"objects":{"obj:1 0 R":{"value":{"/S":"/JavaScript","/JS":"AFDate_KeystrokeEx(\"yyyy\");"}},"obj:2 0 R":{"value":{"/S":"/Launch","/F":"manual.exe"}},"obj:3 0 R":{"value":{"/S":"/URI","/URI":"https://example.invalid"}}}}'
  $map=Get-ObjectMap ($json|ConvertFrom-Json -AsHashtable -Depth 20)
  $actions=@(Get-PdfActions $map 500)
  if(@($actions|Where-Object Classification -eq 'RecognizedAdobeFormDateValidation').Count -ne 1){throw 'Self-test failed: recognized Adobe JavaScript.'}
  $launch=@($actions|Where-Object ActionType -eq 'Launch')
  if($launch.Count -ne 1 -or $launch[0].Target -notmatch 'manual\.exe'){throw 'Self-test failed: Launch target extraction.'}
  $collision='{"Key":1,"key":2}'|ConvertFrom-Json -AsHashtable
  if($collision.Count -ne 2){throw 'Self-test failed: case-distinct JSON keys.'}

  $tempFile=Join-Path ([IO.Path]::GetTempPath()) ('PeeDeeEff-NonPdf-'+[guid]::NewGuid().ToString('N')+'.txt')
  try {
    Set-Content -LiteralPath $tempFile -Value 'not a pdf' -Encoding utf8
    if((Get-PdfHeaderOffset $tempFile) -ne -1){throw 'Self-test failed: non-PDF detection.'}
    $record=New-ResultRecord (Get-Item -LiteralPath $tempFile)
    if($record.IsPdf -ne $false){throw 'Self-test failed: non-PDF result initialization.'}
    $selfTestTemp=Join-Path ([IO.Path]::GetTempPath()) ('PeeDeeEff-SelfTest-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $selfTestTemp -Force
    try {
      $inspected=Inspect-File -File (Get-Item -LiteralPath $tempFile) -TempPath $selfTestTemp -MaximumBytes 1MB
      if($inspected.Disposition -ne 'NOT A PDF' -or $inspected.Errors){throw 'Self-test failed: non-PDF end-to-end disposition.'}
    }
    finally {Remove-Item -LiteralPath $selfTestTemp -Recurse -Force -ErrorAction SilentlyContinue}
  }
  finally {Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue}
  Write-Status PASS 'Regression self-tests passed.'
}

function Inspect-File {
  param([IO.FileInfo]$File,[string]$TempPath,[long]$MaximumBytes)
  Write-Host '';Write-Host "FILE: $($File.FullName)" -ForegroundColor White;Write-Host ('-'*96) -ForegroundColor DarkGray
  $result=New-ResultRecord $File
  $findings=[Collections.Generic.List[string]]::new();$info=[Collections.Generic.List[string]]::new();$errors=[Collections.Generic.List[string]]::new()
  try {
    $result.SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
    Write-Status INFO ("Size: {0:N0} | SHA-256: {1}"-f$File.Length,$result.SHA256)
    Write-Status INFO 'Checking file signature and extension consistency.'
    $result.PdfHeaderOffset=Get-PdfHeaderOffset $File.FullName
    $result.IsPdf=$result.PdfHeaderOffset -ge 0
    $extensionSaysPdf=$File.Extension -ieq '.pdf'
    $result.ExtensionMatchesContent=$extensionSaysPdf -eq $result.IsPdf

    if(-not$result.IsPdf){
      if($extensionSaysPdf){
        $result.Disposition='REJECT';$result.Risk='High';$findings.Add('PDF extension but no PDF header')
        Write-Status FAIL 'Extension is .pdf, but no %PDF- header was found within the first 1024 bytes.'
      } else {
        $result.Disposition='NOT A PDF';$result.Risk='Not assessed'
        Write-Status SKIP 'No PDF content signature detected; qpdf was not invoked.'
      }
      $result.Findings=$findings -join '; '
      return [pscustomobject]$result
    }

    if($extensionSaysPdf){Write-Status PASS 'Extension and PDF content signature agree.'}
    else{$findings.Add('PDF content uses non-PDF extension');Write-Status WARN "PDF content detected despite extension '$($File.Extension)'."}
    if($result.PdfHeaderOffset -eq 0){Write-Status PASS 'PDF magic signature begins at byte 0.'}
    else{$findings.Add("PDF header at byte $($result.PdfHeaderOffset)");Write-Status WARN "PDF header begins at byte $($result.PdfHeaderOffset); inspect for leading or polyglot data."}

    Write-Status INFO 'Running qpdf structural, encryption, JSON object, action, normalization, and PE checks.'
    $q=Invoke-QpdfAnalysis $File.FullName $TempPath $MaximumBytes $EvidenceLength
    $result.QpdfVersion=$q.Version;$result.QpdfExitCode=$q.CheckExitCode;$result.QpdfWarningClass=$q.WarningClass;$result.QpdfWarningCount=$q.WarningCount;$result.QpdfWarningSummary=$q.WarningSummary;$result.QpdfCheckOutput=$q.CheckOutput
    $result.QpdfJsonCompleted=$q.JsonCompleted;$result.QpdfJsonError=$q.JsonError;$result.QpdfObjectCount=$q.JsonObjectCount
    $result.IsEncrypted=$q.IsEncrypted;$result.EmptyUserPassword=$q.EmptyUserPassword;$result.PermissionOnlyEncryption=$q.PermissionOnlyEncryption;$result.EncryptionRevision=$q.EncryptionRevision;$result.QpdfPermissions=$q.Permissions
    $result.JavaScriptActionCount=$q.JavaScriptCount;$result.RecognizedAdobeJavaScriptCount=$q.RecognizedAdobeJavaScriptCount;$result.HighRiskJavaScriptCount=$q.HighRiskJavaScriptCount;$result.UnclassifiedJavaScriptCount=$q.UnclassifiedJavaScriptCount;$result.JavaScriptObjects=$q.JavaScriptObjects;$result.JavaScriptEvidence=$q.JavaScriptEvidence
    $result.LaunchActionCount=$q.LaunchCount;$result.LaunchObjects=$q.LaunchObjects;$result.LaunchTargets=$q.LaunchTargets;$result.SubmitFormActionCount=$q.SubmitFormCount;$result.RemoteActionCount=$q.RemoteActionCount;$result.UriActionCount=$q.UriActionCount;$result.NamedActionCount=$q.NamedActionCount;$result.ActionSummary=$q.ActionSummary
    $result.NormalizationCompleted=$q.NormalizationCompleted;$result.ConfirmedPECount=$q.PECount;$result.ConfirmedPortableExecutable=$q.PECount-gt 0;$result.PEDetails=$q.PEDetails
    $result.AnalysisComplete=$q.JsonCompleted -and $q.NormalizationCompleted -and $q.CheckExitCode -in 0,3

    if($q.CheckExitCode-eq 0){Write-Status PASS 'qpdf structural validation completed without warnings.'}
    elseif($q.CheckExitCode-eq 3){Write-Status WARN "qpdf completed with $($q.WarningCount) warning(s): $($q.WarningClass)"}
    else{Write-Status FAIL "qpdf structural validation failed with exit code $($q.CheckExitCode)."}
    if($q.JsonCompleted){Write-Status PASS "qpdf JSON object analysis completed across $($q.JsonObjectCount) objects."}else{Write-Status FAIL "qpdf JSON object analysis failed: $($q.JsonError)"}
    if($q.NormalizationCompleted){Write-Status PASS 'qpdf normalization completed.'}else{Write-Status FAIL 'qpdf normalization failed.'}

    if($q.PermissionOnlyEncryption){$result.PasswordLikelyRequired='No - empty user password';$info.Add("Permission-only encryption; R=$($q.EncryptionRevision)");Write-Status INFO 'Permission-only encryption detected; no opening password is required.'}
    elseif($q.IsEncrypted){$result.PasswordLikelyRequired='Yes or unresolved';$findings.Add('Encrypted without confirmed empty user password');Write-Status WARN 'Encryption present without confirmed empty opening password.'}
    else{$result.PasswordLikelyRequired='No';Write-Status PASS 'File is not encrypted.'}

    if($q.JavaScriptCount -eq 0){Write-Status PASS 'No JavaScript action dictionaries detected.'}
    else{
      if($q.RecognizedAdobeJavaScriptCount){Write-Status WARN "Recognized Adobe form JavaScript actions: $($q.RecognizedAdobeJavaScriptCount)";$info.Add("Recognized Adobe form JavaScript: $($q.RecognizedAdobeJavaScriptCount)")}
      if($q.UnclassifiedJavaScriptCount){Write-Status FAIL "Unclassified JavaScript actions: $($q.UnclassifiedJavaScriptCount)";$findings.Add("Unclassified JavaScript actions: $($q.JavaScriptObjects)")}
      if($q.HighRiskJavaScriptCount){Write-Status FAIL "High-risk JavaScript primitives: $($q.HighRiskJavaScriptCount)";$findings.Add("High-risk JavaScript actions: $($q.JavaScriptObjects)")}
    }
    if($q.LaunchCount){Write-Status FAIL "Launch actions: $($q.LaunchCount) | Targets: $($q.LaunchTargets)";$findings.Add("Launch actions: $($q.LaunchObjects); targets: $($q.LaunchTargets)")}else{Write-Status PASS 'No Launch actions detected.'}
    if($q.SubmitFormCount){Write-Status FAIL "SubmitForm actions: $($q.SubmitFormCount)";$findings.Add("SubmitForm actions: $($q.SubmitFormCount)")}else{Write-Status PASS 'No SubmitForm actions detected.'}
    if($q.RemoteActionCount){Write-Status WARN "Remote document actions: $($q.RemoteActionCount)";$findings.Add("Remote document actions: $($q.RemoteActionCount)")}else{Write-Status PASS 'No remote document actions detected.'}
    if($q.UriActionCount){Write-Status INFO "URI actions: $($q.UriActionCount)";$info.Add("URI actions: $($q.UriActionCount)")}else{Write-Status PASS 'No URI actions detected.'}
    if($q.NamedActionCount){Write-Status INFO "Named actions: $($q.NamedActionCount)";$info.Add("Named actions: $($q.NamedActionCount)")}else{Write-Status PASS 'No Named actions detected.'}
    if($q.PECount){Write-Status FAIL "Validated Windows PE structures: $($q.PECount)";$findings.Add("Validated PE structures: $($q.PECount)")}else{Write-Status PASS 'No valid Windows PE structure detected.'}

    if(-not$q.JsonCompleted){$findings.Add('qpdf JSON analysis incomplete')}
    if(-not$q.NormalizationCompleted){$findings.Add('qpdf normalization incomplete')}
    if($q.WarningClass-ne'None'){$info.Add("qpdf warnings: $($q.WarningClass)")}

    $fatal=$q.CheckExitCode-notin 0,3
    $high=$q.HighRiskJavaScriptCount -or $q.UnclassifiedJavaScriptCount -or $q.LaunchCount -or $q.SubmitFormCount -or $q.PECount -or $fatal
    $medium=$q.RecognizedAdobeJavaScriptCount -or $q.RemoteActionCount -or ($q.IsEncrypted -and -not$q.PermissionOnlyEncryption)
    $incomplete=-not$result.AnalysisComplete
    $low=$q.WarningClass-match'ReconstructedStructure|OtherWarning' -or $result.PdfHeaderOffset-ne 0
    if($high){$result.Risk='High';$result.Disposition='QUARANTINE / MANUAL REVIEW'}
    elseif($medium){$result.Risk='Medium';$result.Disposition='MANUAL REVIEW'}
    elseif($incomplete){$result.Risk='Unknown';$result.Disposition='ANALYSIS INCOMPLETE'}
    elseif($low){$result.Risk='Low';$result.Disposition='REVIEW'}
    else{$result.Risk='No selected indicators detected';$result.Disposition='PASS FIRST-LINE CHECKS'}
    Write-Status INFO "Disposition: $($result.Disposition) | Risk: $($result.Risk)"
  }
  catch{$errors.Add($_.Exception.Message);$result.Risk='Unknown';$result.Disposition='ERROR';Write-Status FAIL $_.Exception.Message}
  $result.Findings=$findings-join'; ';$result.Informational=$info-join'; ';$result.Errors=$errors-join'; '
  return [pscustomobject]$result
}

Write-Banner
$qpdf=Get-Command qpdf -ErrorAction SilentlyContinue
if(-not$qpdf){throw 'qpdf is required. Install QPDF and ensure qpdf.exe is in PATH.'}
if($RunSelfTest){Invoke-SelfTest}
$target=Get-Item -LiteralPath (Resolve-Path -LiteralPath $Path) -Force
if(-not$target.PSIsContainer){throw 'Path must be a folder.'}
if([string]::IsNullOrWhiteSpace($OutputDirectory)){$OutputDirectory=Join-Path $target.FullName 'PeeDeeEff-Results'}
$null=New-Item -ItemType Directory -Path $OutputDirectory -Force
$OutputDirectory=(Resolve-Path $OutputDirectory).Path
$temp=Join-Path ([IO.Path]::GetTempPath()) ('PeeDeeEff-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try{
  $files=@(Get-ChildItem -LiteralPath $target.FullName -File -Force -Recurse:$Recurse|Where-Object{-not$_.FullName.StartsWith($OutputDirectory,[StringComparison]::OrdinalIgnoreCase)})
  Write-Status INFO "Files discovered: $($files.Count)"
  $results=[Collections.Generic.List[object]]::new();$n=0;$max=[long]$MaxReadMB*1MB
  foreach($file in $files){$n++;Write-Progress -Activity 'PeeDeeEff' -Status "$n/$($files.Count): $($file.Name)" -PercentComplete ($n/$files.Count*100);$results.Add((Inspect-File $file $temp $max))}
  Write-Progress -Activity PeeDeeEff -Completed
  $groups=@($results|Where-Object SHA256|Group-Object SHA256)
  foreach($group in $groups){foreach($item in $group.Group){$item.DuplicateGroupSize=$group.Count}}
  $stamp=Get-Date -Format yyyyMMdd-HHmmss
  $csv=Join-Path $OutputDirectory "PeeDeeEff-Results-$stamp.csv"
  $json=Join-Path $OutputDirectory "PeeDeeEff-Results-$stamp.json"
  $results|Export-Csv $csv -NoTypeInformation -Encoding utf8
  $results|ConvertTo-Json -Depth 10|Set-Content $json -Encoding utf8
  Write-Host '';Write-Host ('='*96) -ForegroundColor DarkGray;Write-Host SUMMARY -ForegroundColor Cyan;Write-Host ('='*96) -ForegroundColor DarkGray
  $results|Group-Object Disposition|Sort-Object Name|ForEach-Object{Write-Host("{0,-34} {1,5}"-f$_.Name,$_.Count)}
  Write-Status INFO "Duplicate hash groups: $(@($groups|Where-Object Count -gt 1).Count)"
  Write-Status INFO "CSV: $csv";Write-Status INFO "JSON: $json"
  Write-Status WARN 'A clean result is not proof of safety. Retain approved antimalware, CDR, access control, and untrusted-content controls.'
}
finally{Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
