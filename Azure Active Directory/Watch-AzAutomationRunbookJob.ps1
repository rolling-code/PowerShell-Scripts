<#
.SYNOPSIS
Monitors an Azure Automation runbook job and displays new stream records until the job finishes.

.DESCRIPTION
Monitors an existing Azure Automation runbook job, periodically reports its current state,
and displays newly available Output, Verbose, Warning, Error, or Progress stream records.

The script can monitor a supplied job ID or resolve the most recent job for a specified
runbook. It reuses the current Azure PowerShell context by default and does not start, stop,
suspend, or modify Azure Automation jobs.

.PARAMETER ResourceGroupName
Name of the resource group containing the Azure Automation account.

.PARAMETER AutomationAccountName
Name of the Azure Automation account.

.PARAMETER RunbookName
Name of the runbook. When JobId is omitted, the script monitors the most recent job for this runbook.

.PARAMETER JobId
Optional Azure Automation job ID. When omitted, the most recent job for RunbookName is selected.

.PARAMETER Streams
Stream to display. Specify Any to display Output, Verbose, Warning, Error, and Progress records.

.PARAMETER PollSeconds
Number of seconds between status checks. The default is 5 seconds.

.PARAMETER MaxWaitMinutes
Maximum monitoring duration in minutes. A value of 0, the default, waits without a time limit.

.PARAMETER AllowInteractiveLogin
Allows the script to call Connect-AzAccount when no current Azure context exists.
Without this switch, the script stops and asks the operator to authenticate separately.

.EXAMPLE
.\Watch-AzAutomationRunbookJob.ps1 `
    -ResourceGroupName "rg-automation" `
    -AutomationAccountName "aa-security-operations" `
    -RunbookName "Invoke-SecurityValidation"

Monitors the latest job for the specified runbook and displays its Output stream.

.EXAMPLE
.\Watch-AzAutomationRunbookJob.ps1 `
    -ResourceGroupName "rg-automation" `
    -AutomationAccountName "aa-security-operations" `
    -RunbookName "Invoke-SecurityValidation" `
    -JobId "00000000-0000-0000-0000-000000000000" `
    -Streams Any `
    -PollSeconds 10

Monitors a specific job and displays all supported job streams every 10 seconds.

.EXAMPLE
.\Watch-AzAutomationRunbookJob.ps1 `
    -ResourceGroupName "rg-automation" `
    -AutomationAccountName "aa-security-operations" `
    -RunbookName "Invoke-SecurityValidation" `
    -AllowInteractiveLogin

Permits an interactive Azure sign-in only if no reusable Az context is available.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ResourceGroupName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $AutomationAccountName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $RunbookName,

    [Parameter()]
    [ValidateScript({
        if ([string]::IsNullOrWhiteSpace($_)) { return $true }
        $parsedGuid = [guid]::Empty
        if (-not [guid]::TryParse($_, [ref] $parsedGuid)) {
            throw 'JobId must be a valid GUID.'
        }
        return $true
    })]
    [string] $JobId,

    [Parameter()]
    [ValidateSet('Output', 'Verbose', 'Warning', 'Error', 'Progress', 'Any')]
    [string] $Streams = 'Output',

    [Parameter()]
    [ValidateRange(1, 3600)]
    [int] $PollSeconds = 5,

    [Parameter()]
    [ValidateRange(0, 525600)]
    [int] $MaxWaitMinutes = 0,

    [Parameter()]
    [switch] $AllowInteractiveLogin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredCommands = @(
    'Get-AzContext',
    'Connect-AzAccount',
    'Get-AzAutomationJob',
    'Get-AzAutomationJobOutput',
    'Get-AzAutomationJobOutputRecord'
)

$missingCommands = @(
    foreach ($command in $requiredCommands) {
        if (-not (Get-Command -Name $command -ErrorAction SilentlyContinue)) {
            $command
        }
    }
)

if ($missingCommands.Count -gt 0) {
    throw "Required Azure PowerShell commands are unavailable: $($missingCommands -join ', '). Install or import the Az.Accounts and Az.Automation modules."
}

$azContext = Get-AzContext -ErrorAction SilentlyContinue
if (-not $azContext) {
    if (-not $AllowInteractiveLogin) {
        throw 'No active Azure context was found. Run Connect-AzAccount first, or rerun with -AllowInteractiveLogin.'
    }

    Write-Verbose 'No active Azure context was found. Starting interactive authentication.'
    $null = Connect-AzAccount
    $azContext = Get-AzContext -ErrorAction Stop
}

Write-Verbose ("Using Azure context for account '{0}' in subscription '{1}' ({2})." -f `
    $azContext.Account.Id,
    $azContext.Subscription.Name,
    $azContext.Subscription.Id)

$jobQueryParameters = @{
    ResourceGroupName     = $ResourceGroupName
    AutomationAccountName = $AutomationAccountName
    ErrorAction           = 'Stop'
}

if ([string]::IsNullOrWhiteSpace($JobId)) {
    Write-Verbose "Resolving the most recent job for runbook '$RunbookName'."

    $job = Get-AzAutomationJob @jobQueryParameters -RunbookName $RunbookName |
        Sort-Object -Property @{ Expression = {
            if ($null -ne $_.StartTime) { $_.StartTime }
            elseif ($null -ne $_.CreationTime) { $_.CreationTime }
            else { [datetime]::MinValue }
        }; Descending = $true } |
        Select-Object -First 1

    if (-not $job) {
        throw "No Azure Automation jobs were found for runbook '$RunbookName'."
    }

    $JobId = [string] $job.JobId
}
else {
    $job = Get-AzAutomationJob @jobQueryParameters -Id $JobId
    if (-not $job) {
        throw "Azure Automation job '$JobId' was not found."
    }

    if ($job.RunbookName -and $job.RunbookName -ne $RunbookName) {
        throw "Job '$JobId' belongs to runbook '$($job.RunbookName)', not '$RunbookName'."
    }
}

$selectedStreams = if ($Streams -eq 'Any') {
    @('Output', 'Verbose', 'Warning', 'Error', 'Progress')
}
else {
    @($Streams)
}

$seenRecordIds = @{}
$seenSummaryKeys = @{}
foreach ($streamName in $selectedStreams) {
    $seenRecordIds[$streamName] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenSummaryKeys[$streamName] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
}

function Write-JobStreamRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Output', 'Verbose', 'Warning', 'Error', 'Progress')]
        [string] $StreamName
    )

    $records = @(
        Get-AzAutomationJobOutput `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName `
            -Id $JobId `
            -Stream $StreamName `
            -ErrorAction Stop
    )

    foreach ($record in $records) {
        $recordId = [string] $record.Id

        if (-not [string]::IsNullOrWhiteSpace($recordId)) {
            if (-not $seenRecordIds[$StreamName].Add($recordId)) {
                continue
            }

            $detail = Get-AzAutomationJobOutputRecord `
                -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -Id $recordId `
                -ErrorAction Stop

            $value = $detail.Value
            if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string] $value)) {
                $value = $record.Summary
            }

            Write-Host ("[{0:u}] [{1}] {2}" -f (Get-Date), $StreamName, ([string] $value))
            continue
        }

        $summary = [string] $record.Summary
        $summaryKey = '{0}|{1}' -f $StreamName, $summary
        if ($seenSummaryKeys[$StreamName].Add($summaryKey)) {
            Write-Host ("[{0:u}] [{1}] {2}" -f (Get-Date), $StreamName, $summary)
        }
    }
}

$terminalStates = @('Completed', 'Failed', 'Stopped', 'Suspended')
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$lastStatusLine = $null

Write-Host ("Monitoring job '{0}' for runbook '{1}' in Automation account '{2}' (resource group '{3}')." -f `
    $JobId,
    $RunbookName,
    $AutomationAccountName,
    $ResourceGroupName) -ForegroundColor Cyan

try {
    while ($true) {
        $job = Get-AzAutomationJob @jobQueryParameters -Id $JobId
        if (-not $job) {
            throw "Azure Automation job '$JobId' is no longer available."
        }

        $statusLine = "Status: $($job.Status) | Started: $($job.StartTime) | Last changed: $($job.LastModifiedTime)"
        if ($statusLine -ne $lastStatusLine) {
            Write-Host ("[{0:u}] {1}" -f (Get-Date), $statusLine)
            $lastStatusLine = $statusLine
        }

        foreach ($streamName in $selectedStreams) {
            Write-JobStreamRecord -StreamName $streamName
        }

        if ([string] $job.Status -in $terminalStates) {
            Write-Host "Job reached terminal state: $($job.Status)" -ForegroundColor Cyan
            break
        }

        if ($MaxWaitMinutes -gt 0 -and $stopwatch.Elapsed.TotalMinutes -ge $MaxWaitMinutes) {
            throw "Monitoring exceeded the configured limit of $MaxWaitMinutes minute(s). The Azure Automation job was not modified."
        }

        Start-Sleep -Seconds $PollSeconds
    }
}
finally {
    $stopwatch.Stop()
}

[pscustomobject]@{
    JobId                = [string] $job.JobId
    RunbookName          = [string] $job.RunbookName
    Status               = [string] $job.Status
    StartTime            = $job.StartTime
    LastModifiedTime     = $job.LastModifiedTime
    MonitoredFor         = $stopwatch.Elapsed
    Streams              = $selectedStreams -join ','
    ResourceGroupName    = $ResourceGroupName
    AutomationAccountName = $AutomationAccountName
}
