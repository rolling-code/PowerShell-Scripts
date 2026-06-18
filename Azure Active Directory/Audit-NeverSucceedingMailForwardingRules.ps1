<#
.SYNOPSIS
  Audits Exchange Online mailbox forwarding and Inbox rules for deterministic "will not succeed" conditions.

.DESCRIPTION
  Outputs CSV evidence for cleanup user stories. This script is conservative: it flags forwarding rules/actions
  that have no resolvable active recipient target, expired date conditions, optional disabled rules, and optional
  external forwarding blocked by the tenant outbound forwarding policy.

.OUTPUTS
  MailForwarding_NeverSucceed_Findings_<timestamp>.csv
  MailForwarding_RuleWarnings_Review_<timestamp>.csv when -IncludeReviewWarnings is used

.NOTES
  Version: 1.2 hotfix
  Fix: removed duplicate -Confidence parameter in MailboxRulesCannotBeEnumerated finding.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = ".",
    [switch]$IncludeDisabledRules,
    [switch]$IncludePolicyBlockedExternalForwarding,
    [switch]$IncludeReviewWarnings,
    [int]$ProgressEvery = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor Cyan
}

function Join-Values {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [string]) { return $Value }
    try {
        return (($Value | ForEach-Object { if ($null -ne $_) { $_.ToString() } }) -join "; ")
    }
    catch { return $Value.ToString() }
}

function Normalize-Text {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return (($Value | Out-String).Trim())
}

function Test-GuidString {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Test-ExternalAddress {
    param(
        [string]$SmtpAddress,
        [string[]]$AcceptedDomains
    )
    if ([string]::IsNullOrWhiteSpace($SmtpAddress) -or $SmtpAddress -notmatch '@') { return $false }
    $clean = $SmtpAddress.ToLowerInvariant().Replace('smtp:','').Trim()
    $domain = ($clean -split '@')[-1]
    return (-not ($AcceptedDomains -contains $domain))
}

$script:RecipientCache = @{}

function Get-CandidateRecipientIdsFromObject {
    param([object]$RecipientObject)

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($null -eq $RecipientObject) { return @() }

    $raw = Normalize-Text $RecipientObject
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

    foreach ($m in [regex]::Matches($raw, '(?i)\[SMTP:([^\]]+)\]')) { [void]$candidates.Add($m.Groups[1].Value.Trim()) }
    foreach ($m in [regex]::Matches($raw, '(?i)\bsmtp:([^;\]\s]+)')) { [void]$candidates.Add($m.Groups[1].Value.Trim()) }
    foreach ($m in [regex]::Matches($raw, '(?i)([A-Z0-9._%+''-]+@[A-Z0-9.-]+\.[A-Z]{2,})')) { [void]$candidates.Add($m.Groups[1].Value.Trim()) }
    foreach ($m in [regex]::Matches($raw, '(?i)\[EX:([^\]]+)\]')) { [void]$candidates.Add($m.Groups[1].Value.Trim()) }
    if ($raw -match '^/o=') { [void]$candidates.Add($raw.Trim()) }
    foreach ($m in [regex]::Matches($raw, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')) { [void]$candidates.Add($m.Value.Trim()) }

    if ($candidates.Count -eq 0) { [void]$candidates.Add($raw.Trim()) }
    return @($candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Resolve-ExchangeRecipientSafe {
    param([string]$Identity)

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        return [pscustomobject]@{
            Status="NoIdentity"; Identity=$Identity; PrimarySmtpAddress=""; RecipientTypeDetails=""; DisplayName="";
            FailureReason="No recipient identity was present."
        }
    }

    $key = $Identity.ToLowerInvariant()
    if ($script:RecipientCache.ContainsKey($key)) { return $script:RecipientCache[$key] }

    $result = $null
    try {
        $r = Get-Recipient -Identity $Identity -ErrorAction Stop
        $result = [pscustomobject]@{
            Status="Resolved"
            Identity=$Identity
            PrimarySmtpAddress=($r.PrimarySmtpAddress.ToString())
            RecipientTypeDetails=($r.RecipientTypeDetails.ToString())
            DisplayName=$r.DisplayName
            FailureReason=""
        }
    }
    catch {
        try {
            $r2 = Get-Recipient -Identity $Identity -IncludeSoftDeletedRecipients -ErrorAction Stop
            $result = [pscustomobject]@{
                Status="SoftDeleted"
                Identity=$Identity
                PrimarySmtpAddress=($r2.PrimarySmtpAddress.ToString())
                RecipientTypeDetails=($r2.RecipientTypeDetails.ToString())
                DisplayName=$r2.DisplayName
                FailureReason="Recipient resolves only as soft-deleted. Forward/redirect cannot reliably deliver to a soft-deleted recipient."
            }
        }
        catch {
            $kind = if (Test-GuidString $Identity) { "UnresolvedGuid" } elseif ($Identity -match '@') { "UnresolvedSmtpOrExternal" } else { "UnresolvedNameOrLegacyDN" }
            $result = [pscustomobject]@{
                Status=$kind
                Identity=$Identity
                PrimarySmtpAddress=""
                RecipientTypeDetails=""
                DisplayName=""
                FailureReason="Recipient could not be resolved in Exchange: $($_.Exception.Message)"
            }
        }
    }

    $script:RecipientCache[$key] = $result
    return $result
}

function Resolve-RecipientActionSet {
    param([object[]]$Recipients)

    $raw = Join-Values $Recipients
    $ids = @()
    foreach ($r in @($Recipients)) { $ids += Get-CandidateRecipientIdsFromObject -RecipientObject $r }
    $ids = @($ids | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

    $resolved = @()
    foreach ($id in $ids) { $resolved += Resolve-ExchangeRecipientSafe -Identity $id }

    $bad = @($resolved | Where-Object { $_.Status -ne "Resolved" })
    $good = @($resolved | Where-Object { $_.Status -eq "Resolved" })

    return [pscustomobject]@{
        Raw=$raw
        CandidateIdentities=($ids -join "; ")
        ResolvedSummary=(($resolved | ForEach-Object { "$($_.Identity) => $($_.Status) $($_.PrimarySmtpAddress)" }) -join " | ")
        AllUnresolved=($ids.Count -gt 0 -and $good.Count -eq 0)
        AnyUnresolved=($bad.Count -gt 0)
        FailureDetails=(($bad | ForEach-Object { "$($_.Identity): $($_.FailureReason)" }) -join " | ")
    }
}

function New-Finding {
    param(
        [string]$FindingType,
        [string]$Confidence = "High",
        [string]$MailboxDisplayName,
        [string]$MailboxUPN,
        [string]$PrimarySmtpAddress,
        [string]$RecipientTypeDetails,
        [string]$RuleName,
        [string]$RuleEnabled,
        [string]$RulePriority,
        [string]$ActionType,
        [string]$TargetRaw,
        [string]$TargetResolution,
        [string]$FailureReason,
        [string]$Evidence,
        [string]$RuleSyntax,
        [string]$SuggestedAction
    )

    [pscustomobject]@{
        FindingType=$FindingType
        Confidence=$Confidence
        MailboxDisplayName=$MailboxDisplayName
        MailboxUPN=$MailboxUPN
        PrimarySmtpAddress=$PrimarySmtpAddress
        RecipientTypeDetails=$RecipientTypeDetails
        RuleName=$RuleName
        RuleEnabled=$RuleEnabled
        RulePriority=$RulePriority
        ActionType=$ActionType
        TargetRaw=$TargetRaw
        TargetResolution=$TargetResolution
        FailureReason=$FailureReason
        Evidence=$Evidence
        RuleSyntax=$RuleSyntax
        SuggestedAction=$SuggestedAction
        CollectedAt=(Get-Date).ToString("s")
    }
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$findingsPath = Join-Path $OutputDirectory "MailForwarding_NeverSucceed_Findings_$timestamp.csv"
$warningsPath = Join-Path $OutputDirectory "MailForwarding_RuleWarnings_Review_$timestamp.csv"

if (-not (Get-Command Get-EXOMailbox -ErrorAction SilentlyContinue)) {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
}

try { Get-OrganizationConfig -ErrorAction Stop | Out-Null }
catch {
    Write-Info "Not connected to Exchange Online. Launching Connect-ExchangeOnline..."
    Connect-ExchangeOnline -ShowBanner:$false
}

Write-Info "Loading accepted domains and outbound forwarding policy state..."
$acceptedDomains = @()
try { $acceptedDomains = @(Get-AcceptedDomain | Select-Object -ExpandProperty DomainName | ForEach-Object { $_.ToString().ToLowerInvariant() }) }
catch { Write-Warning "Could not read accepted domains: $($_.Exception.Message)" }

$outboundPolicies = @()
try { $outboundPolicies = @(Get-HostedOutboundSpamFilterPolicy | Select-Object Name,IsDefault,AutoForwardingMode) }
catch { Write-Warning "Could not read outbound spam policies: $($_.Exception.Message)" }

$defaultOutboundPolicy = @($outboundPolicies | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1)
$externalForwardingGenerallyBlocked = $false
if ($null -ne $defaultOutboundPolicy) {
    if ($defaultOutboundPolicy.AutoForwardingMode -in @("Off", "Automatic")) { $externalForwardingGenerallyBlocked = $true }
}

Write-Info "Collecting user and shared mailboxes..."
$mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox,SharedMailbox -Properties DisplayName,UserPrincipalName,PrimarySmtpAddress,RecipientTypeDetails,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward,RulesQuota)
Write-Info "Mailbox count: $($mailboxes.Count)"

$findings = New-Object System.Collections.Generic.List[object]
$warnings = New-Object System.Collections.Generic.List[object]
$idx = 0

foreach ($mbx in $mailboxes) {
    $idx++
    if ($ProgressEvery -gt 0 -and ($idx % $ProgressEvery -eq 0)) { Write-Info "Checked $idx / $($mailboxes.Count) mailboxes..." }

    $mbxPrimary = $mbx.PrimarySmtpAddress.ToString()
    $mbxType = $mbx.RecipientTypeDetails.ToString()

    # Mailbox-level ForwardingAddress target resolution.
    if ($null -ne $mbx.ForwardingAddress) {
        $res = Resolve-RecipientActionSet -Recipients @($mbx.ForwardingAddress)
        if ($res.AllUnresolved) {
            $findings.Add((New-Finding `
                -FindingType "MailboxForwardingTargetUnresolved" `
                -Confidence "High" `
                -MailboxDisplayName $mbx.DisplayName `
                -MailboxUPN $mbx.UserPrincipalName `
                -PrimarySmtpAddress $mbxPrimary `
                -RecipientTypeDetails $mbxType `
                -RuleName "Mailbox-level forwarding" `
                -RuleEnabled "Enabled" `
                -RulePriority "N/A" `
                -ActionType "ForwardingAddress" `
                -TargetRaw $res.Raw `
                -TargetResolution $res.ResolvedSummary `
                -FailureReason "Mailbox-level ForwardingAddress cannot be resolved to an active Exchange recipient." `
                -Evidence $res.FailureDetails `
                -RuleSyntax "Get-Mailbox shows ForwardingAddress='$($mbx.ForwardingAddress)', ForwardingSmtpAddress='$($mbx.ForwardingSmtpAddress)', DeliverToMailboxAndForward='$($mbx.DeliverToMailboxAndForward)'" `
                -SuggestedAction "Validate business need. If no longer required, clear forwarding with Set-Mailbox -Identity '$mbxPrimary' -ForwardingAddress `$null -DeliverToMailboxAndForward `$false."))
        }
    }

    # Optional: mailbox-level SMTP forwarding blocked by policy.
    if ($IncludePolicyBlockedExternalForwarding -and $null -ne $mbx.ForwardingSmtpAddress) {
        $smtpTarget = $mbx.ForwardingSmtpAddress.ToString()
        if ((Test-ExternalAddress -SmtpAddress $smtpTarget -AcceptedDomains $acceptedDomains) -and $externalForwardingGenerallyBlocked) {
            $findings.Add((New-Finding `
                -FindingType "MailboxForwardingBlockedByOutboundPolicy" `
                -Confidence "Medium-High" `
                -MailboxDisplayName $mbx.DisplayName `
                -MailboxUPN $mbx.UserPrincipalName `
                -PrimarySmtpAddress $mbxPrimary `
                -RecipientTypeDetails $mbxType `
                -RuleName "Mailbox-level forwarding" `
                -RuleEnabled "Enabled" `
                -RulePriority "N/A" `
                -ActionType "ForwardingSmtpAddress" `
                -TargetRaw $smtpTarget `
                -TargetResolution "External SMTP target; default outbound spam policy AutoForwardingMode=$($defaultOutboundPolicy.AutoForwardingMode)" `
                -FailureReason "Automatic external forwarding is blocked by outbound spam policy; action will be blocked/NDR while policy remains in this state." `
                -Evidence "ForwardingSmtpAddress=$smtpTarget" `
                -RuleSyntax "Get-Mailbox shows ForwardingSmtpAddress='$smtpTarget', DeliverToMailboxAndForward='$($mbx.DeliverToMailboxAndForward)'" `
                -SuggestedAction "If not approved, remove mailbox forwarding. If required, use a tightly scoped exception and document business approval."))
        }
    }

    # Inbox rules.
    $localWarnings = @()
    $rules = @()
    try {
        $rules = @(Get-InboxRule -Mailbox $mbxPrimary -IncludeHidden -WarningVariable localWarnings -WarningAction Continue -ErrorAction Stop)
    }
    catch {
        $findings.Add((New-Finding `
            -FindingType "MailboxRulesCannotBeEnumerated" `
            -Confidence "Review" `
            -MailboxDisplayName $mbx.DisplayName `
            -MailboxUPN $mbx.UserPrincipalName `
            -PrimarySmtpAddress $mbxPrimary `
            -RecipientTypeDetails $mbxType `
            -RuleName "N/A" `
            -RuleEnabled "Unknown" `
            -RulePriority "N/A" `
            -ActionType "Get-InboxRule" `
            -TargetRaw "" `
            -TargetResolution "" `
            -FailureReason "Could not enumerate Inbox rules for mailbox." `
            -Evidence $_.Exception.Message `
            -RuleSyntax "N/A" `
            -SuggestedAction "Sysadmin should verify mailbox state/permissions and re-run Get-InboxRule. This is not a rule-removal finding by itself."))
        continue
    }

    if ($IncludeReviewWarnings) {
        foreach ($w in $localWarnings) {
            $warnings.Add([pscustomobject]@{
                MailboxDisplayName=$mbx.DisplayName
                MailboxUPN=$mbx.UserPrincipalName
                PrimarySmtpAddress=$mbxPrimary
                Warning=$w.ToString()
                CollectedAt=(Get-Date).ToString("s")
            })
        }
    }

    foreach ($rule in $rules) {
        $ruleName = $rule.Name
        $ruleSyntax = Normalize-Text $rule.Description
        $ruleEnabled = $rule.Enabled.ToString()
        $rulePriority = if ($null -ne $rule.Priority) { $rule.Priority.ToString() } else { "" }

        if ($IncludeDisabledRules -and $rule.Enabled -eq $false) {
            $findings.Add((New-Finding `
                -FindingType "InboxRuleDisabledWillNotExecute" `
                -Confidence "High while disabled" `
                -MailboxDisplayName $mbx.DisplayName `
                -MailboxUPN $mbx.UserPrincipalName `
                -PrimarySmtpAddress $mbxPrimary `
                -RecipientTypeDetails $mbxType `
                -RuleName $ruleName `
                -RuleEnabled $ruleEnabled `
                -RulePriority $rulePriority `
                -ActionType "RuleEnabled" `
                -TargetRaw "" `
                -TargetResolution "" `
                -FailureReason "Inbox rule is disabled and will not execute while it remains disabled." `
                -Evidence "Enabled=False" `
                -RuleSyntax $ruleSyntax `
                -SuggestedAction "Confirm with mailbox owner/application owner. If intentionally obsolete, remove the disabled rule. Note: disabled rules do not count toward enabled-rule quota but still add review noise."))
        }

        try {
            if ($null -ne $rule.ReceivedBeforeDate -and ([datetime]$rule.ReceivedBeforeDate) -lt (Get-Date)) {
                $findings.Add((New-Finding `
                    -FindingType "InboxRuleExpiredDateCondition" `
                    -Confidence "High" `
                    -MailboxDisplayName $mbx.DisplayName `
                    -MailboxUPN $mbx.UserPrincipalName `
                    -PrimarySmtpAddress $mbxPrimary `
                    -RecipientTypeDetails $mbxType `
                    -RuleName $ruleName `
                    -RuleEnabled $ruleEnabled `
                    -RulePriority $rulePriority `
                    -ActionType "ReceivedBeforeDate" `
                    -TargetRaw $rule.ReceivedBeforeDate.ToString() `
                    -TargetResolution "N/A" `
                    -FailureReason "Rule requires incoming mail to have a ReceivedBeforeDate that is already in the past; it will not match future incoming messages." `
                    -Evidence "ReceivedBeforeDate=$($rule.ReceivedBeforeDate); CurrentDate=$(Get-Date)" `
                    -RuleSyntax $ruleSyntax `
                    -SuggestedAction "Validate if this was a past temporary workflow. If obsolete, remove it."))
            }
        }
        catch { }

        $actions = @(
            [pscustomobject]@{ Name="ForwardTo"; Value=$rule.ForwardTo },
            [pscustomobject]@{ Name="RedirectTo"; Value=$rule.RedirectTo },
            [pscustomobject]@{ Name="ForwardAsAttachmentTo"; Value=$rule.ForwardAsAttachmentTo }
        )

        foreach ($action in $actions) {
            $rawAction = Join-Values $action.Value
            if ([string]::IsNullOrWhiteSpace($rawAction)) { continue }

            $res = Resolve-RecipientActionSet -Recipients @($action.Value)
            if ($res.AllUnresolved) {
                $findings.Add((New-Finding `
                    -FindingType "InboxRuleActionTargetUnresolved" `
                    -Confidence "High" `
                    -MailboxDisplayName $mbx.DisplayName `
                    -MailboxUPN $mbx.UserPrincipalName `
                    -PrimarySmtpAddress $mbxPrimary `
                    -RecipientTypeDetails $mbxType `
                    -RuleName $ruleName `
                    -RuleEnabled $ruleEnabled `
                    -RulePriority $rulePriority `
                    -ActionType $action.Name `
                    -TargetRaw $res.Raw `
                    -TargetResolution $res.ResolvedSummary `
                    -FailureReason "The $($action.Name) action has no resolvable active recipient target. This forwarding/redirect action will not succeed." `
                    -Evidence $res.FailureDetails `
                    -RuleSyntax $ruleSyntax `
                    -SuggestedAction "Validate business need. If the rule exists only to forward/redirect to this target, remove the rule. If it has other valid actions, remove or correct the invalid target."))
            }

            if ($IncludePolicyBlockedExternalForwarding -and $externalForwardingGenerallyBlocked) {
                $candidateIds = @($res.CandidateIdentities -split '; ' | Where-Object { $_ -match '@' })
                foreach ($smtp in $candidateIds) {
                    if (Test-ExternalAddress -SmtpAddress $smtp -AcceptedDomains $acceptedDomains) {
                        $findings.Add((New-Finding `
                            -FindingType "InboxRuleExternalForwardingBlockedByOutboundPolicy" `
                            -Confidence "Medium-High" `
                            -MailboxDisplayName $mbx.DisplayName `
                            -MailboxUPN $mbx.UserPrincipalName `
                            -PrimarySmtpAddress $mbxPrimary `
                            -RecipientTypeDetails $mbxType `
                            -RuleName $ruleName `
                            -RuleEnabled $ruleEnabled `
                            -RulePriority $rulePriority `
                            -ActionType $action.Name `
                            -TargetRaw $smtp `
                            -TargetResolution "External SMTP target; default outbound spam policy AutoForwardingMode=$($defaultOutboundPolicy.AutoForwardingMode)" `
                            -FailureReason "Automatic external forwarding is blocked by outbound spam policy; action will be blocked/NDR while policy remains in this state." `
                            -Evidence "Rule action target=$smtp" `
                            -RuleSyntax $ruleSyntax `
                            -SuggestedAction "If external forwarding is not approved, remove this rule. If required, use a tightly scoped exception and document business approval."))
                    }
                }
            }
        }
    }
}

Write-Info "Exporting findings to $findingsPath"
$findings | Sort-Object FindingType,MailboxUPN,RulePriority,RuleName | Export-Csv -Path $findingsPath -NoTypeInformation -Encoding UTF8

if ($IncludeReviewWarnings) {
    Write-Info "Exporting review warnings to $warningsPath"
    $warnings | Export-Csv -Path $warningsPath -NoTypeInformation -Encoding UTF8
}

Write-Host ""
Write-Host "Summary" -ForegroundColor Green
Write-Host "-------" -ForegroundColor Green
Write-Host "Mailboxes checked: $($mailboxes.Count)"
Write-Host "Findings exported: $($findings.Count)"
Write-Host "Findings CSV: $findingsPath"
if ($IncludeReviewWarnings) {
    Write-Host "Review warnings exported: $($warnings.Count)"
    Write-Host "Warnings CSV: $warningsPath"
}
Write-Host ""
Write-Host "Recommended conservative run:" -ForegroundColor Yellow
Write-Host ".\Audit-NeverSucceedingMailForwardingRules_v1.2.ps1 -OutputDirectory . -IncludeReviewWarnings"
Write-Host ""
Write-Host "Broader run, including disabled rules and policy-blocked external forwarding:" -ForegroundColor Yellow
Write-Host ".\Audit-NeverSucceedingMailForwardingRules_v1.2.ps1 -OutputDirectory . -IncludeDisabledRules -IncludePolicyBlockedExternalForwarding -IncludeReviewWarnings"
