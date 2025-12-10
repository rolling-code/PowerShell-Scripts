
param(
  [Parameter(Mandatory)] [string] $ResourceGroupName,
  [Parameter(Mandatory)] [string] $AutomationAccountName,
  [Parameter(Mandatory)] [string] $RunbookName,
  [string] $JobId = "",
  [ValidateSet('Output','Verbose','Warning','Error','Progress','Any')] [string] $Streams = 'Output',
  [int] $PollSeconds = 5
)

if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }

# Resolve JobId if not supplied
if ([string]::IsNullOrWhiteSpace($JobId)) {
  $job = Get-AzAutomationJob -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName |
         Sort-Object StartTime -Descending | Select-Object -First 1
  if (-not $job) { Write-Error "No jobs found for runbook '$RunbookName'."; return }
  $JobId = $job.JobId
}

Write-Host "Watching JobId: $JobId for runbook '$RunbookName' in '$AutomationAccountName' (RG: $ResourceGroupName)..." -ForegroundColor Cyan

# Dedupe per stream
$seen = @{
  Output  = [System.Collections.Generic.HashSet[string]]::new()
  Verbose = [System.Collections.Generic.HashSet[string]]::new()
  Warning = [System.Collections.Generic.HashSet[string]]::new()
  Error   = [System.Collections.Generic.HashSet[string]]::new()
  Progress= [System.Collections.Generic.HashSet[string]]::new()
}

function Print-Stream {
  param([string]$stream)

  # 1) List job-level stream entries (summary)
  $records = Get-AzAutomationJobOutput -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Id $JobId -Stream $stream

  foreach ($r in $records) {
    $rid = $r.Id
    # Use rid when present; fall back to Summary otherwise
    if ($rid) {
      if (-not $seen[$stream].Contains($rid)) {
        $seen[$stream].Add($rid) | Out-Null
        $rec = Get-AzAutomationJobOutputRecord -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Id $rid
        Write-Host ("[{0}] [{1}] {2}" -f (Get-Date), $stream, $rid) -ForegroundColor Green
        if ($rec.Value) {
          try { ($rec.Value | ConvertFrom-Json) | ConvertTo-Json -Depth 8 } catch { $rec.Value }
        } else {
          $r.Summary
        }
      }
    } else {
      # Summary-only entry with no record id
      Write-Host ("[{0}] [{1}] (no Id)" -f (Get-Date), $stream) -ForegroundColor Yellow
      $r.Summary
    }
  }
}

# Main polling loop
while ($true) {
  $j = Get-AzAutomationJob -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Id $JobId
  
  $j = Get-AzAutomationJob -ResourceGroupName $ResourceGroupName `
                         -AutomationAccountName $AutomationAccountName `
                         -Id $JobId

  if (-not $j) {
    Write-Host ("[{0}] Status: (not yet available) JobId:{1}" -f (Get-Date), $JobId) -ForegroundColor Yellow
    Start-Sleep -Seconds $PollSeconds
    continue
  }

  Write-Host ("[{0}] Status: {1}  Started:{2}  LastChange:{3}" -f (Get-Date), $j.Status, $j.StartTime, $j.LastModifiedTime)

  if ($Streams -eq 'Any') { foreach ($s in @('Output','Verbose','Warning','Error','Progress')) { Print-Stream -stream $s } }
  else { Print-Stream -stream $Streams }

  if ($j.Status -in 'Completed','Failed','Stopped','Suspended') {
    Write-Host "Job reached terminal state: $($j.Status)" -ForegroundColor Cyan
    # one last pass
    if ($Streams -eq 'Any') { foreach ($s in @('Output','Verbose','Warning','Error','Progress')) { Print-Stream -stream $s } }
    else { Print-Stream -stream $Streams }
    break
  }

  Start-Sleep -Seconds $PollSeconds
}
