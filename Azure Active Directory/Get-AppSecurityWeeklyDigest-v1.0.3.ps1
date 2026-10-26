#Requires -Version 5.1
<#
.SYNOPSIS
  Runs five read-only Microsoft Entra app-security checks and exports four finding CSV files.
.VERSION
  1.0.3
#>
[CmdletBinding()]
param(
  [ValidateRange(1,3650)][int]$OldAppAgeDays = 365,
  [string]$OutputDirectory = (Join-Path (Get-Location) 'AppSecurityWeeklyDigest'),
  [string[]]$HighRiskPermissions = @(
    'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.ReadWrite.All',
    'Group.ReadWrite.All','Mail.Read','Mail.ReadWrite','Mail.Send',
    'RoleManagement.ReadWrite.Directory','User.ReadWrite.All'
  ),
  [switch]$PassThru
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ToolVersion = '1.0.3'
$Started = Get-Date

function Write-Step([string]$Text){ Write-Host "[>] $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text){ Write-Host "[+] $Text" -ForegroundColor Green }
function Write-Warn([string]$Text){ Write-Host "[!] $Text" -ForegroundColor Yellow }
function Export-FindingCsv {
  [CmdletBinding()]
  param(
    [Parameter()][AllowNull()][AllowEmptyCollection()][object[]]$Rows = @(),
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string[]]$Columns
  )
  $safeRows = @($Rows | Where-Object { $null -ne $_ })
  if ($safeRows.Count -gt 0) {
    $safeRows | Select-Object -Property $Columns | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
  } else {
    (($Columns | ForEach-Object { '"' + ($_ -replace '"','""') + '"' }) -join ',') |
      Set-Content -LiteralPath $Path -Encoding UTF8
  }
}

$required = @('Connect-MgGraph','Get-MgContext','Get-MgApplication','Get-MgApplicationOwner',
  'Get-MgServicePrincipal','Get-MgServicePrincipalAppRoleAssignedTo')
$missing = @($required | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
if($missing.Count){ throw "Missing Graph command(s): $($missing -join ', '). Install/update Microsoft.Graph." }

Write-Host ''
Write-Host '  APP SECURITY WEEKLY DIGEST' -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "  Version $ToolVersion | Read-only Microsoft Graph assessment" -ForegroundColor DarkGray
Write-Host ''

$scope='Application.Read.All'
$ctx=Get-MgContext -ErrorAction SilentlyContinue
if(-not $ctx -or -not (@($ctx.Scopes) -contains $scope)){
  Write-Step "Connecting to Microsoft Graph with $scope"
  Connect-MgGraph -Scopes $scope -NoWelcome | Out-Null
  $ctx=Get-MgContext
}else{ Write-Ok "Reusing Microsoft Graph connection for $($ctx.Account)" }
if(-not (@($ctx.Scopes) -contains $scope)){ throw "Active Graph session lacks $scope." }

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$runDir=Join-Path $OutputDirectory (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$now=Get-Date
$expired=@(); $ownerless=@(); $old=@(); $high=@(); $errors=@()

Write-Step 'Retrieving all app registrations'
$apps=@(Get-MgApplication -All -Property 'Id,AppId,DisplayName,CreatedDateTime,PasswordCredentials')
Write-Ok "Retrieved $($apps.Count) app registration(s)"
Write-Step 'Checking expired secrets, owners, and app age'
for($i=0;$i -lt $apps.Count;$i++){
  $app=$apps[$i]
  $name=if([string]::IsNullOrWhiteSpace($app.DisplayName)){'<unnamed>'}else{[string]$app.DisplayName}
  Write-Progress -Activity 'Assessing app registrations' -Status "$($i+1) of $($apps.Count) - $name" -PercentComplete ((($i+1)/[Math]::Max($apps.Count,1))*100)
  $age=$null
  if($app.CreatedDateTime){
    $age=[int](New-TimeSpan -Start ([DateTimeOffset]$app.CreatedDateTime).LocalDateTime -End $now).TotalDays
    if($age -ge $OldAppAgeDays){
      $old += [pscustomobject]@{DisplayName=$name;AppId=[string]$app.AppId;ApplicationObjectId=[string]$app.Id;CreatedDateTime=$app.CreatedDateTime;AgeDays=$age;ThresholdDays=$OldAppAgeDays}
    }
  }
  foreach($secret in @($app.PasswordCredentials)){
    if(-not $secret.EndDateTime){continue}
    $end=([DateTimeOffset]$secret.EndDateTime).LocalDateTime
    if($end -lt $now){
      $expired += [pscustomobject]@{DisplayName=$name;AppId=[string]$app.AppId;ApplicationObjectId=[string]$app.Id;SecretDisplayName=[string]$secret.DisplayName;KeyId=[string]$secret.KeyId;StartDateTime=$secret.StartDateTime;EndDateTime=$secret.EndDateTime;DaysExpired=[int](New-TimeSpan -Start $end -End $now).TotalDays}
    }
  }
  try{
    $owners=@(Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction Stop)
    if($owners.Count -eq 0){
      $ownerless += [pscustomobject]@{DisplayName=$name;AppId=[string]$app.AppId;ApplicationObjectId=[string]$app.Id;CreatedDateTime=$app.CreatedDateTime;AgeDays=$age;OwnerCount=0}
    }
  }catch{
    $errors += [pscustomobject]@{Stage='Application owners';ObjectName=$name;ObjectId=[string]$app.Id;Error=$_.Exception.Message}
  }
}
Write-Progress -Activity 'Assessing app registrations' -Completed

Write-Step 'Retrieving Microsoft Graph permission definitions'
$graphMatches=@(Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Property 'Id,AppId,DisplayName,AppRoles')
if($graphMatches.Count -ne 1){throw "Expected one Microsoft Graph service principal; found $($graphMatches.Count)."}
$graph=$graphMatches[0]; $roleMap=@{}
foreach($r in @($graph.AppRoles)){if($r.Id -and $r.Value){$roleMap[[string]$r.Id]=[string]$r.Value}}

Write-Step 'Retrieving all service principals'
$sps=@(Get-MgServicePrincipal -All -Property 'Id,AppId,DisplayName,ServicePrincipalType,AccountEnabled')
$spById=@{}; foreach($sp in $sps){$spById[[string]$sp.Id]=$sp}
Write-Ok "Retrieved $($sps.Count) service principal(s)"
Write-Step 'Checking high-risk Microsoft Graph application permissions'
try{
  $assignments=@(Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $graph.Id -All -ErrorAction Stop)
  foreach($g in @($assignments | Group-Object PrincipalId)){
    $sp=$spById[[string]$g.Name]; if($null -eq $sp){continue}
    $matched=@($g.Group | ForEach-Object{$roleMap[[string]$_.AppRoleId]} | Where-Object{$_ -and ($HighRiskPermissions -contains $_)} | Sort-Object -Unique)
    foreach($permission in $matched){
      $high += [pscustomobject]@{DisplayName=if($sp.DisplayName){[string]$sp.DisplayName}else{'<unnamed>'};AppId=[string]$sp.AppId;ServicePrincipalObjectId=[string]$sp.Id;ServicePrincipalType=[string]$sp.ServicePrincipalType;AccountEnabled=$sp.AccountEnabled;Resource='Microsoft Graph';Permission=[string]$permission;PermissionType='Application'}
    }
  }
}catch{
  $errors += [pscustomobject]@{Stage='Microsoft Graph app-role assignments';ObjectName='Microsoft Graph';ObjectId=[string]$graph.Id;Error=$_.Exception.Message}
}

$p1=Join-Path $runDir '1-Expired-Secrets.csv'
$p2=Join-Path $runDir '2-Apps-With-No-Owner.csv'
$p3=Join-Path $runDir ("3-Apps-{0}Plus-Days-Old.csv" -f $OldAppAgeDays)
$p4=Join-Path $runDir '4-High-Risk-Permissions.csv'
$pe=Join-Path $runDir 'Collection-Errors.csv'
$ps=Join-Path $runDir 'Summary.json'
Export-FindingCsv -Rows $expired -Path $p1 -Columns @('DisplayName','AppId','ApplicationObjectId','SecretDisplayName','KeyId','StartDateTime','EndDateTime','DaysExpired')
Export-FindingCsv -Rows $ownerless -Path $p2 -Columns @('DisplayName','AppId','ApplicationObjectId','CreatedDateTime','AgeDays','OwnerCount')
Export-FindingCsv -Rows $old -Path $p3 -Columns @('DisplayName','AppId','ApplicationObjectId','CreatedDateTime','AgeDays','ThresholdDays')
Export-FindingCsv -Rows $high -Path $p4 -Columns @('DisplayName','AppId','ServicePrincipalObjectId','ServicePrincipalType','AccountEnabled','Resource','Permission','PermissionType')
Export-FindingCsv -Rows $errors -Path $pe -Columns @('Stage','ObjectName','ObjectId','Error')

$uniqueHigh=@($high | Select-Object -ExpandProperty ServicePrincipalObjectId -Unique).Count
$flagged=@($expired.Count,$ownerless.Count,$old.Count,$uniqueHigh | Where-Object{$_ -gt 0}).Count
$risk=if($flagged -ge 3){'HIGH'}elseif($flagged -ge 1){'MEDIUM'}else{'LOW'}
$summary=[pscustomobject]@{GeneratedUtc=[DateTime]::UtcNow.ToString('o');TenantId=$ctx.TenantId;Account=$ctx.Account;TotalAppRegistrations=$apps.Count;ExpiredSecrets=$expired.Count;AppsWithNoOwner=$ownerless.Count;AppsAtLeastOldAppAgeDays=$old.Count;OldAppAgeDays=$OldAppAgeDays;ServicePrincipalsWithHighRiskGraphPermissions=$uniqueHigh;HighRiskPermissionAssignments=$high.Count;FindingCategoriesFlagged=$flagged;OverallRisk=$risk;CollectionErrors=$errors.Count;DurationSeconds=[Math]::Round(((Get-Date)-$Started).TotalSeconds,2);OutputDirectory=$runDir}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ps -Encoding UTF8

Write-Host ''
Write-Host '  APP SECURITY WEEKLY DIGEST' -ForegroundColor White -BackgroundColor DarkBlue
foreach($m in @(@('Total app registrations',$apps.Count,$false),@('Expired secrets',$expired.Count,($expired.Count-gt 0)),@('Apps with no owner',$ownerless.Count,($ownerless.Count-gt 0)),@("Apps $OldAppAgeDays+ days old",$old.Count,($old.Count-gt 0)),@('High-risk permissions',$uniqueHigh,($uniqueHigh-gt 0)))){
  Write-Host ("  {0,-28}: {1,6} {2}" -f $m[0],$m[1],$(if($m[2]){'[!]'}else{'[OK]'})) -ForegroundColor $(if($m[2]){'Red'}else{'Green'})
}
Write-Host ''
Write-Host "  Overall risk                : $risk" -ForegroundColor $(if($risk-eq'HIGH'){'Red'}elseif($risk-eq'MEDIUM'){'Yellow'}else{'Green'})
Write-Host "  Collection errors           : $($errors.Count)" -ForegroundColor $(if($errors.Count){'Yellow'}else{'Green'})
Write-Host ''
Write-Ok "1. Expired secrets: $p1"
Write-Ok "2. Apps with no owner: $p2"
Write-Ok "3. Old apps: $p3"
Write-Ok "4. High-risk permissions: $p4"
Write-Ok "Run summary: $ps"
if($errors.Count){Write-Warn "Collection errors: $pe"}
if($PassThru){$summary}
