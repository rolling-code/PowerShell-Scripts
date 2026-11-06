#requires -Version 7.2
<#
.SYNOPSIS
  Read-only GitHub repository security-enforcement assessment with CSV, JSON, Excel, and HTML evidence.
.VERSION
  1.4.1
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string[]]$Repository,
 [ValidateRange(1,100)][int]$CommitSampleSize=20,
 [string]$OutputDirectory=(Join-Path $PWD ('GitHubRepositorySecurity-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))),
 [string]$SecurityPattern='(?i)(codeql|code[ -]?scanning|bandit|pip[-_ ]?audit|trivy|semgrep|snyk|security|dependency[ -]?review|secret[ -]?scan|gitleaks|grype|osv|bearer|sonar|devskim)',
 [switch]$FailOnNotEnforced
)
Set-StrictMode -Version 3.0;$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$Version='1.4.1';$Started=[datetime]::UtcNow;$ApiVersion='2022-11-28'
$Summary=[Collections.Generic.List[object]]::new();$Tests=[Collections.Generic.List[object]]::new();$Commits=[Collections.Generic.List[object]]::new();$Features=[Collections.Generic.List[object]]::new();$Errors=[Collections.Generic.List[object]]::new();$Workflows=[Collections.Generic.List[object]]::new();$Rules=[Collections.Generic.List[object]]::new()
function Msg($k,$m,$c){Write-Host ('[{0}] [{1}] {2}'-f(Get-Date -Format HH:mm:ss),$k,$m)-ForegroundColor $c}
function Prop($o,$n){if($null -eq $o){return $null};$p=$o.PSObject.Properties[$n];if($null -eq $p){return $null};$p.Value}
function ConvertTo-HtmlSafe($v){if($null -eq $v){return ''};[Net.WebUtility]::HtmlEncode([string]$v)}
function Invoke-GhApi($ep,$repo,$stage,[switch]$AllowFailure){$x=& gh.exe api -H 'Accept: application/vnd.github+json' -H "X-GitHub-Api-Version: $ApiVersion" $ep 2>&1;if($LASTEXITCODE -ne 0){$m=($x|Out-String).Trim();if($AllowFailure){$Errors.Add([pscustomobject]@{TimestampUtc=[datetime]::UtcNow.ToString('o');Repository=$repo;Stage=$stage;Message=$m});return $null};throw "GitHub API failed: $ep. $m"};$t=($x|Out-String).Trim();if(!$t){return $null};$t|ConvertFrom-Json -Depth 100}
function AddTest($r,$t,$e,$a,$result,$cmd){$Tests.Add([pscustomobject]@{Repository=$r;Test=$t;Expected=$e;Actual=$a;Result=$result;EvidenceCommand=$cmd})}
function NewReport($path,$csv,$json,$xlsx,$errCsv,$identity){
 function StateClass([string]$state){if($state -match '^(Enabled|Configured|Observed|Required|Present)$'){return 'good'};if($state -match '^(Disabled|Not enabled|Not configured|Not required|Not observed)$'){return 'bad'};return 'warn'}
 function ErrorFor([string]$repo,[string]$stage){$e=@($Errors|Where-Object{$_.Repository-eq$repo-and$_.Stage-eq$stage}|Select-Object -Last 1);if($e.Count){return [string]$e[0].Message};return ''}
 function FeatureStatus([string]$repo,[string]$name){$f=@($Features|Where-Object{$_.Repository-eq$repo-and$_.Feature-eq$name}|Select-Object -Last 1);if($f.Count){return [string]$f[0].Status};return 'Unknown'}
 function FeatureRow([string]$name,[string]$state,[string]$notes){$cl=StateClass $state;return "<tr><td>$(ConvertTo-HtmlSafe $name)</td><td class='$cl'>$(ConvertTo-HtmlSafe $state)</td><td><pre>$(ConvertTo-HtmlSafe $notes)</pre></td></tr>"}
 function CommitFeatureRow([string]$feature,[string]$state,[string]$notes){$cl=StateClass $state;return "<tr><td>$(ConvertTo-HtmlSafe $feature)</td><td class='$cl'>$(ConvertTo-HtmlSafe $state)</td><td>$(ConvertTo-HtmlSafe $notes)</td></tr>"}

 $not=@($Summary|Where-Object{$_.EnforcementState-notin@('ENFORCED_AND_OBSERVED','ENFORCED_CODEQL_DEFAULT_SETUP')}).Count
 $repoSections=foreach($r in $Summary){
  $repo=[string]$r.Repository
  $workflowError=ErrorFor $repo 'Workflow inventory'
  $codeQlError=ErrorFor $repo 'CodeQL default setup'
  $analysisError=ErrorFor $repo 'Code scanning analyses'
  $advanced=FeatureStatus $repo 'advanced_security'
  $secret=FeatureStatus $repo 'secret_scanning'
  $pushProtect=FeatureStatus $repo 'secret_scanning_push_protection'
  $depUpdates=FeatureStatus $repo 'dependabot_security_updates'
  $workflowState=if([int]$r.SecurityWorkflowCount-gt0){'Configured'}else{'Not configured'}
  $pushState=if([int]$r.SecurityWorkflowsOnPush-gt0){'Configured'}else{'Not configured'}
  $prState=if([int]$r.SecurityWorkflowsOnPullRequest-gt0){'Configured'}else{'Not configured'}
  $requiredState=if([int]$r.RequiredSecurityCheckCount-gt0){'Required'}else{'Not required'}
  $checkState=if([int]$r.CommitsWithAnyCheckRun-gt0){'Observed'}else{'Not observed'}
  $codeState=if([string]$r.CodeSecurity-eq'Not enabled'){'Not enabled'}elseif([string]$r.CodeSecurity-match'enabled|present'){'Enabled'}else{'Unknown'}
  $workflowNote=if($workflowError){$workflowError}else{"HTTP 200; $($r.SecurityWorkflowCount) security workflow(s) found on $($r.DefaultBranch)."}
  $codeNote=if($codeQlError){$codeQlError}else{"HTTP 200; Code Security state: $($r.CodeSecurity)."}
  $analysisNote=if($analysisError){$analysisError}else{'HTTP 200; code-scanning analyses endpoint was accessible.'}
  $featureRows=@(
   FeatureRow 'GitHub Advanced Security' $(if($advanced-eq'enabled'){'Enabled'}elseif($advanced-eq'disabled'){'Disabled'}else{'Unknown'}) "HTTP 200 GET /repos/$repo; security_and_analysis.advanced_security.status=$advanced"
   FeatureRow 'GitHub Code Security / Code scanning' $codeState $codeNote
   FeatureRow 'Code scanning analyses' $(if($analysisError){'Not enabled'}else{'Observed'}) $analysisNote
   FeatureRow 'Secret scanning' $(if($secret-eq'enabled'){'Enabled'}elseif($secret-eq'disabled'){'Disabled'}else{'Unknown'}) "HTTP 200 GET /repos/$repo; security_and_analysis.secret_scanning.status=$secret"
   FeatureRow 'Secret scanning push protection' $(if($pushProtect-eq'enabled'){'Enabled'}elseif($pushProtect-eq'disabled'){'Disabled'}else{'Unknown'}) "HTTP 200 GET /repos/$repo; security_and_analysis.secret_scanning_push_protection.status=$pushProtect"
   FeatureRow 'Dependabot security updates' $(if($depUpdates-eq'enabled'){'Enabled'}elseif($depUpdates-eq'disabled'){'Disabled'}else{'Unknown'}) "HTTP 200 GET /repos/$repo; security_and_analysis.dependabot_security_updates.status=$depUpdates"
   FeatureRow 'Security workflow on default branch' $workflowState $workflowNote
   FeatureRow 'Security workflow trigger: push' $pushState "$($r.SecurityWorkflowsOnPush) security workflow(s) on $($r.DefaultBranch) declare a push trigger."
   FeatureRow 'Security workflow trigger: pull request' $prState "$($r.SecurityWorkflowsOnPullRequest) security workflow(s) on $($r.DefaultBranch) declare a pull_request or pull_request_target trigger."
   FeatureRow 'Required security status checks' $requiredState "HTTP 200 rules evaluation for $($r.DefaultBranch); $($r.RequiredSecurityCheckCount) required security check context(s) matched."
   FeatureRow 'GitHub Actions check runs on sampled commits' $checkState "HTTP 200 check-runs queries; $($r.CommitsWithAnyCheckRun) of $($r.SampledCommitCount) sampled commit(s) had any check run."
  )
  $commitSections=foreach($c in @($Commits|Where-Object{$_.Repository-eq$repo})){
   $short=([string]$c.CommitSha).Substring(0,[Math]::Min(12,([string]$c.CommitSha).Length))
   $names=[string]$c.AllCheckNames
   $tools=@(
    @{N='GitHub Actions check runs';P='.';S=([int]$c.TotalCheckRuns-gt0);Note="$($c.TotalCheckRuns) total check run(s) returned by HTTP 200 check-runs query."},
    @{N='CodeQL / GitHub code scanning check';P='(?i)codeql|code[ -]?scanning';S=($names-match'(?i)codeql|code[ -]?scanning')},
    @{N='Dependency Review';P='(?i)dependency[ -]?review';S=($names-match'(?i)dependency[ -]?review')},
    @{N='Secret scanning CI check';P='(?i)secret[ -]?scan|gitleaks';S=($names-match'(?i)secret[ -]?scan|gitleaks')},
    @{N='Bandit';P='(?i)bandit';S=($names-match'(?i)bandit')},
    @{N='pip-audit';P='(?i)pip[-_ ]?audit';S=($names-match'(?i)pip[-_ ]?audit')},
    @{N='pytest';P='(?i)pytest';S=($names-match'(?i)pytest')},
    @{N='Ruff';P='(?i)ruff';S=($names-match'(?i)ruff')}
   )
   $toolRows=foreach($tool in $tools){$state=if($tool.S){'Observed'}else{'Not observed'};$note=if($tool.ContainsKey('Note')-and-not[string]::IsNullOrWhiteSpace([string]$tool['Note'])){[string]$tool['Note']}elseif([int]$c.TotalCheckRuns-eq0){'HTTP 200; the commit had 0 check runs, so this check was not reported to GitHub.'}else{"Check names returned: $names"};CommitFeatureRow $tool.N $state $note}
   "<section class='commit'><h4><code>$short</code> | $(ConvertTo-HtmlSafe $c.CommitDate)</h4><div class='wrap'><table><thead><tr><th>GitHub security feature / check</th><th>State</th><th>Notes</th></tr></thead><tbody>$($toolRows -join "`n")</tbody></table></div></section>"
  }
  "<section class='repo'><h2>$(ConvertTo-HtmlSafe $repo)</h2><p><b>Default branch:</b> $(ConvertTo-HtmlSafe $r.DefaultBranch) | <b>Assessment:</b> <span class='bad'>$(ConvertTo-HtmlSafe $r.EnforcementState)</span></p><h3>Repository security features</h3><div class='wrap'><table><thead><tr><th>GitHub security feature</th><th>State</th><th>Notes</th></tr></thead><tbody>$($featureRows -join "`n")</tbody></table></div><h3>Commit-level evidence</h3>$($commitSections -join "`n")</section>"
 }
 $links=@(
  @{Name='GitHub Code Security and code scanning';Url='https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning'},
  @{Name='GitHub Secret scanning';Url='https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning'},
  @{Name='GitHub Secret scanning push protection';Url='https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations'},
  @{Name='Dependabot alerts';Url='https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-alerts'},
  @{Name='Dependabot security updates';Url='https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates'},
  @{Name='Required status checks';Url='https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches'},
  @{Name='GitHub Actions workflows';Url='https://docs.github.com/en/actions/writing-workflows/about-workflows'}
 )
 $featureLinks=foreach($l in $links){"<li><a href='$($l.Url)'>$(ConvertTo-HtmlSafe $l.Name)</a></li>"}
 @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GitHub Repository Security Assessment</title><style>:root{--n:#12304a;--b:#1f4e79;--l:#d8e0e8;--g:#12733d;--r:#b42318;--w:#a15c00}body{font-family:Segoe UI,Arial;margin:0;color:#18212a;line-height:1.42}header{background:var(--n);color:white;padding:24px 5%}main{max-width:1100px;margin:auto;padding:20px 4%}h2{color:var(--n);border-bottom:2px solid var(--b);padding-bottom:5px}h3{color:var(--b)}h4{margin-bottom:6px}.call{border-left:6px solid var(--r);background:#fff2f0;padding:14px}.wrap{overflow-x:auto;border:1px solid var(--l)}table{border-collapse:collapse;width:100%;font-size:13px}th{background:var(--b);color:white;text-align:left;padding:8px}td{border-top:1px solid var(--l);padding:8px;vertical-align:top}tr:nth-child(even){background:#f8fafc}.good{color:var(--g);font-weight:bold}.bad{color:var(--r);font-weight:bold}.warn{color:var(--w);font-weight:bold}pre{white-space:pre-wrap;margin:0;font:12px Consolas,monospace}code{background:#eef2f6;padding:2px 4px}.repo{margin:22px 0}.commit{margin:12px 0;padding:0;border:0}footer{margin-top:24px;border-top:1px solid var(--l);padding-top:12px;font-size:12px}</style></head><body><header><h1>GitHub Repository Security Assessment</h1><p>Read-only point-in-time report | Script v$Version | $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss UTC')) | GitHub identity: $(ConvertTo-HtmlSafe $identity)</p></header><main>
<h2>Executive summary</h2><div class="call"><b>Conclusion:</b> GitHub-hosted security testing and merge enforcement were not demonstrated for $not of $($Summary.Count) assessed repositories. Disabled states are taken from repository metadata. The Code Security conclusion uses GitHub's explicit HTTP 403 response stating that Code Security must be enabled. Commit conclusions use HTTP 200 check-runs responses.</div>
$($repoSections -join "`n")
<h2>GitHub features checked</h2><p>The assessment checked the following native GitHub controls and commit-visible checks:</p><ul>$($featureLinks -join "`n")</ul>
<footer>Point-in-time evidence only. This report does not exclude developer-local testing or an external CI/CD system that does not report results back to GitHub. Such testing is not GitHub-enforced unless checks are reported to GitHub and required before merge.</footer></main></body></html>
"@|Set-Content $path -Encoding utf8
}

Msg INFO "Starting v$Version read-only assessment" Gray
if(!(Get-Command gh -ErrorAction SilentlyContinue)){throw 'GitHub CLI not found'};$auth=& gh.exe auth status 2>&1;if($LASTEXITCODE){throw 'GitHub CLI not authenticated'};$viewer=Invoke-GhApi '/user' '' 'Viewer';Msg PASS "GitHub identity: $($viewer.login)" Green
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null;$OutputDirectory=(Resolve-Path $OutputDirectory).Path
foreach($repoName in $Repository){if($repoName -notmatch '^[^/]+/[^/]+$'){throw "Invalid repository: $repoName"};$owner,$repo=$repoName.Split('/',2);Msg STEP "Assessing $repoName" Cyan;$info=Invoke-GhApi "/repos/$owner/$repo" $repoName Metadata;$branch=[string](Prop $info 'default_branch');$sa=Prop $info 'security_and_analysis'
 foreach($n in @('advanced_security','secret_scanning','secret_scanning_push_protection','dependabot_security_updates')){$f=Prop $sa $n;$st=if($f){[string](Prop $f 'status')}else{'UnknownOrNotVisible'};$Features.Add([pscustomobject]@{Repository=$repoName;Feature=$n;Status=$st;Interpretation=$(if($st-eq'disabled'){'Repository metadata explicitly reports disabled.'}elseif($st-eq'enabled'){'Repository metadata explicitly reports enabled.'}else{'Unknown does not prove disabled; permissions or plan may limit visibility.'});EvidenceSource="GET /repos/$owner/$repo"})}
 $wfRaw=Invoke-GhApi "/repos/$owner/$repo/contents/.github/workflows?ref=$branch" $repoName 'Workflow inventory' -AllowFailure;$secWf=@();foreach($wf in @($wfRaw)){if([string](Prop $wf type) -ne 'file'){continue};$path=[string](Prop $wf path);$enc=($path.Split('/')|%{[uri]::EscapeDataString($_)}) -join '/';$co=Invoke-GhApi "/repos/$owner/$repo/contents/${enc}?ref=$branch" $repoName 'Workflow content' -AllowFailure;if(!$co){continue};$txt=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(([string](Prop $co content) -replace '\s','')));$push=$txt -match '(?im)^\s*push\s*:';$pr=$txt -match '(?im)^\s*pull_request(?:_target)?\s*:';$is=$path -match $SecurityPattern -or $txt -match $SecurityPattern;$row=[pscustomobject]@{Repository=$repoName;Path=$path;IsSecurityWorkflow=$is;TriggersPush=$push;TriggersPullRequest=$pr};$Workflows.Add($row);if($is){$secWf+=,$row}}
 $pushWf=@($secWf|? TriggersPush);$prWf=@($secWf|? TriggersPullRequest);$rulesRaw=Invoke-GhApi "/repos/$owner/$repo/rules/branches/${branch}?per_page=100" $repoName Rules -AllowFailure;$required=@();foreach($r in @($rulesRaw)){$type=[string](Prop $r type);$params=Prop $r parameters;$cx=@();if($type -eq 'required_status_checks'){$cx=@(Prop $params required_status_checks);$required+=@($cx|%{Prop $_ context})};$Rules.Add([pscustomobject]@{Repository=$repoName;RuleType=$type;RequiredStatusChecks=$required -join '; ';EvidenceSource="GET /repos/$owner/$repo/rules/branches/$branch"})};$reqSec=@($required|?{$_ -match $SecurityPattern})
 $cq=Invoke-GhApi "/repos/$owner/$repo/code-scanning/default-setup" $repoName 'CodeQL default setup' -AllowFailure;$cqState=if($cq){[string](Prop $cq state)}else{'UnknownOrNotVisible'};$ar=Invoke-GhApi "/repos/$owner/$repo/code-scanning/analyses?ref=refs/heads/$branch&per_page=100" $repoName 'Code scanning analyses' -AllowFailure;$aa=@();if($ar){$aa=@($ar)};$explicit=@($Errors|?{$_.Repository -eq $repoName -and $_.Message -match 'Code Security must be enabled'}).Count -gt 0;$codeSec=if($explicit){'Not enabled'}elseif($cqState -eq 'configured'){'CodeQL enabled'}elseif($aa.Count){'Code scanning evidence present'}else{'Unknown or not visible'};$Features.Add([pscustomobject]@{Repository=$repoName;Feature='code_security';Status=$codeSec;Interpretation='Explicit 403 is treated as not enabled; otherwise unknown remains unknown.';EvidenceSource="GET /repos/$owner/$repo/code-scanning/default-setup"})
 $commitRaw=Invoke-GhApi "/repos/$owner/$repo/commits?sha=$branch&per_page=$CommitSampleSize" $repoName Commits;$list=@($commitRaw);$any=0;$sec=0;$ok=0;foreach($c in $list){$sha=[string](Prop $c sha);$rr=Invoke-GhApi "/repos/$owner/$repo/commits/$sha/check-runs?per_page=100" $repoName Checks -AllowFailure;$runs=@();if($rr){$runs=@(Prop $rr check_runs)};$sr=@($runs|?{([string](Prop $_ name)) -match $SecurityPattern -or ([string](Prop (Prop $_ app) name)) -match $SecurityPattern});$success=@($sr|?{[string](Prop $_ status) -eq 'completed'-and[string](Prop $_ conclusion)-in@('success','neutral','skipped')});if($runs.Count){$any++};if($sr.Count){$sec++};if($success.Count){$ok++};$Commits.Add([pscustomobject]@{Repository=$repoName;CommitSha=$sha;CommitDate=Prop (Prop (Prop $c commit) committer) date;TotalCheckRuns=$runs.Count;SecurityCheckRuns=$sr.Count;HasSecurityCheck=$sr.Count -gt 0;SecurityCheckNames=($sr|%{Prop $_ name}) -join '; ';AllCheckNames=($runs|%{Prop $_ name}) -join '; '})}
 $count=$list.Count;$all=$count -gt 0 -and $sec -eq $count;$state=if($pushWf.Count -and $reqSec.Count -and $all){'ENFORCED_AND_OBSERVED'}elseif($pushWf.Count -and $reqSec.Count){'ENFORCED_BUT_COMMIT_COVERAGE_GAPS'}elseif($pushWf.Count){'CONFIGURED_NOT_ENFORCED'}elseif($cqState -eq 'configured'-and$reqSec.Count){'ENFORCED_CODEQL_DEFAULT_SETUP'}elseif($cqState -eq 'configured'){'CODEQL_CONFIGURED_NOT_PROVEN_REQUIRED'}else{'NOT_PROVEN'};$recommend='Enable Code Security where licensed; enable CodeQL for Python; run CodeQL, Bandit, pip-audit, pytest, Ruff, and secret detection on push and pull request; require checks on main; enable Secret Protection and push protection where licensed.';$Summary.Add([pscustomobject]@{Repository=$repoName;DefaultBranch=$branch;SecurityWorkflowCount=$secWf.Count;SecurityWorkflowsOnPush=$pushWf.Count;SecurityWorkflowsOnPullRequest=$prWf.Count;RequiredSecurityCheckCount=$reqSec.Count;CodeSecurity=$codeSec;SampledCommitCount=$count;CommitsWithAnyCheckRun=$any;CommitsWithSecurityCheck=$sec;CommitsWithSuccessfulSecurityCheck=$ok;EnforcementState=$state;Recommendation=$recommend})
 AddTest $repoName 'Security workflow exists' 'At least 1' "$($secWf.Count)" $(if($secWf.Count){'PASS'}else{'FAIL'}) "gh api /repos/$owner/$repo/contents/.github/workflows?ref=$branch";AddTest $repoName 'Workflow on push' 'At least 1' "$($pushWf.Count)" $(if($pushWf.Count){'PASS'}else{'FAIL'}) 'Inspect on.push';AddTest $repoName 'Workflow on pull request' 'At least 1' "$($prWf.Count)" $(if($prWf.Count){'PASS'}else{'FAIL'}) 'Inspect on.pull_request';AddTest $repoName 'Required security check' 'At least 1' "$($reqSec.Count)" $(if($reqSec.Count){'PASS'}else{'FAIL'}) "gh api /repos/$owner/$repo/rules/branches/$branch";AddTest $repoName 'Code Security enabled' 'Enabled' $codeSec $(if($codeSec-in@('CodeQL enabled','Code scanning evidence present')){'PASS'}elseif($codeSec -eq 'Not enabled'){'FAIL'}else{'UNKNOWN'}) "gh api /repos/$owner/$repo/code-scanning/default-setup";AddTest $repoName 'Every sampled commit scanned' "$count of $count" "$sec of $count" $(if($all){'PASS'}else{'FAIL'}) "gh api /repos/$owner/$repo/commits/SHA/check-runs";Msg $(if($state -like 'ENFORCED*'){'PASS'}else{'FAIL'}) "${repoName}: $state" $(if($state -like 'ENFORCED*'){'Green'}else{'Red'})
}
$ts=Get-Date -Format yyyyMMdd-HHmmss;$csv=Join-Path $OutputDirectory "Repository-Security-Summary-$ts.csv";$json=Join-Path $OutputDirectory "Repository-Security-Evidence-$ts.json";$xlsx=Join-Path $OutputDirectory "Repository-Security-Assessment-$ts.xlsx";$err=Join-Path $OutputDirectory "Repository-Security-Errors-$ts.csv";$html=Join-Path $OutputDirectory "Repository-Security-Report-$ts.html";$Summary|Export-Csv $csv -NoTypeInformation -Encoding utf8;if($Errors.Count){$Errors|Export-Csv $err -NoTypeInformation -Encoding utf8};[ordered]@{ScriptVersion=$Version;GeneratedUtc=[datetime]::UtcNow.ToString('o');GitHubIdentity=$viewer.login;Repositories=$Summary;Tests=$Tests;Workflows=$Workflows;Rules=$Rules;Features=$Features;Commits=$Commits;Errors=$Errors}|ConvertTo-Json -Depth 20|Set-Content $json -Encoding utf8
if(Get-Module -ListAvailable ImportExcel){Import-Module ImportExcel;$Summary|Export-Excel $xlsx -WorksheetName Summary -TableName SummaryTable -TableStyle Medium2 -AutoSize -FreezeTopRow -BoldTopRow;foreach($d in @(@{N='Expected vs Actual';R=$Tests},@{N='Workflows';R=$Workflows},@{N='Rules';R=$Rules},@{N='Features';R=$Features},@{N='Recent Commits';R=$Commits},@{N='Errors';R=$Errors})){$rows=@($d.R);if(!$rows.Count){$rows=@([pscustomobject]@{Status='No records returned'})};$rows|Export-Excel $xlsx -WorksheetName $d.N -TableName (($d.N -replace '[^A-Za-z0-9]','')+'Table') -TableStyle Medium2 -AutoSize -FreezeTopRow -BoldTopRow -Append}}
NewReport $html $csv $json $xlsx $err ([string]$viewer.login);Msg PASS "HTML report: $html" Green;Msg PASS "Raw CSV: $csv" Green;Msg PASS "JSON evidence: $json" Green;if(Test-Path $xlsx){Msg PASS "Excel: $xlsx" Green};$Summary|Format-Table Repository,DefaultBranch,SecurityWorkflowCount,RequiredSecurityCheckCount,SampledCommitCount,CommitsWithSecurityCheck,CodeSecurity,EnforcementState -AutoSize
if($FailOnNotEnforced-and@($Summary|?{$_.EnforcementState -notlike 'ENFORCED*'}).Count){exit 2}
