#requires -Version 7.0
<#
.SYNOPSIS
Reports disabled Microsoft Entra users who still have assigned licenses.

.DESCRIPTION
Read-only Microsoft Graph audit. Reuses the Microsoft Graph session already connected
in the current PowerShell process and never calls Connect-MgGraph or requests new scopes.
Uses User.Read.All and Directory.Read.All when those permissions are already present.
Exports one row per disabled user and license SKU, with direct/group assignment details
when Microsoft Graph returns licenseAssignmentStates.

.PARAMETER ExportCsv
Detailed CSV output path.

.PARAMETER SummaryCsv
Optional per-user summary CSV path.

.PARAMETER IncludeGuests
Include disabled guest users. Disabled Member users are reported by default.

.EXAMPLE
Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All"
./Get-DisabledUsersLicenses-NoNewConsent.ps1 -ExportCsv ./disabled_licenses.csv
#>

[CmdletBinding()]
param(
    [string]$ExportCsv = (Join-Path $PWD 'disabled_licenses.csv'),
    [string]$SummaryCsv,
    [switch]$IncludeGuests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($commandName in @('Get-MgContext','Get-MgUser','Get-MgSubscribedSku','Get-MgGroup')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command '$commandName' was not found. Install the relevant Microsoft Graph PowerShell modules."
    }
}

$context = Get-MgContext -ErrorAction SilentlyContinue
if ($null -eq $context) {
    throw 'No Microsoft Graph context exists in this PowerShell process. Connect-MgGraph first using permissions already approved in your tenant, then rerun this script in the same window.'
}

$currentScopes = @($context.Scopes)
$missingScopes = @(@('User.Read.All','Directory.Read.All') | Where-Object { $_ -notin $currentScopes })
if (@($missingScopes).Count -gt 0) {
    throw "The current Graph session is missing: $($missingScopes -join ', '). This script will not request new permissions. Reconnect using permissions already approved in your tenant."
}

Write-Host "Reusing Microsoft Graph session for $($context.Account). No new consent request will be made." -ForegroundColor Cyan

$skuMap = @{}
try {
    foreach ($sku in @(Get-MgSubscribedSku -All -Property SkuId,SkuPartNumber -ErrorAction Stop)) {
        $skuId = [string]$sku.SkuId
        if (-not [string]::IsNullOrWhiteSpace($skuId)) {
            $skuMap[$skuId.ToLowerInvariant()] = [string]$sku.SkuPartNumber
        }
    }
    Write-Host "Subscribed SKUs resolved: $($skuMap.Count)" -ForegroundColor DarkGray
}
catch {
    Write-Warning "Could not enumerate subscribed SKUs. GUIDs will be retained: $($_.Exception.Message)"
}

$filter = if ($IncludeGuests) { 'accountEnabled eq false' } else { "accountEnabled eq false and userType eq 'Member'" }
$users = @(
    Get-MgUser -Filter $filter -All `
        -Property Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,AssignedLicenses,LicenseAssignmentStates,OnPremisesSyncEnabled `
        -ErrorAction Stop
)
Write-Host "Disabled users found: $($users.Count)" -ForegroundColor Cyan

$groupCache = @{}
function Resolve-GroupName {
    param([string]$GroupId)
    if ([string]::IsNullOrWhiteSpace($GroupId)) { return $null }
    if ($groupCache.ContainsKey($GroupId)) { return $groupCache[$GroupId] }
    try {
        $groupCache[$GroupId] = [string](Get-MgGroup -GroupId $GroupId -Property DisplayName -ErrorAction Stop).DisplayName
    }
    catch {
        $groupCache[$GroupId] = '[Unresolved group]'
    }
    return $groupCache[$GroupId]
}

$details = [System.Collections.Generic.List[object]]::new()
$counter = 0
foreach ($user in $users) {
    $counter++
    if ($counter % 200 -eq 0) { Write-Host "Processed $counter users..." -ForegroundColor DarkGray }

    $states = @($user.LicenseAssignmentStates)
    if ($states.Count -eq 0) {
        $states = @(
            foreach ($license in @($user.AssignedLicenses)) {
                [pscustomobject]@{
                    SkuId = $license.SkuId
                    AssignedByGroup = $null
                    State = 'Unknown'
                    Error = $null
                    LastUpdatedDateTime = $null
                }
            }
        )
    }

    foreach ($state in $states) {
        $skuId = [string]$state.SkuId
        if ([string]::IsNullOrWhiteSpace($skuId)) { continue }
        $skuKey = $skuId.ToLowerInvariant()
        $groupId = [string]$state.AssignedByGroup
        $assignmentType = if ([string]::IsNullOrWhiteSpace($groupId)) { 'Direct' } else { 'Group' }

        $details.Add([pscustomobject]@{
            DisplayName           = $user.DisplayName
            UserPrincipalName     = $user.UserPrincipalName
            Mail                  = $user.Mail
            UserId                = $user.Id
            UserType              = $user.UserType
            AccountEnabled        = $user.AccountEnabled
            OnPremisesSyncEnabled = $user.OnPremisesSyncEnabled
            SkuPartNumber         = if ($skuMap.ContainsKey($skuKey)) { $skuMap[$skuKey] } else { '[Unknown SKU]' }
            SkuId                 = $skuId
            AssignmentType        = $assignmentType
            AssignedByGroupId     = if ($assignmentType -eq 'Group') { $groupId } else { $null }
            AssignedByGroupName   = if ($assignmentType -eq 'Group') { Resolve-GroupName $groupId } else { $null }
            AssignmentState       = [string]$state.State
            AssignmentError       = [string]$state.Error
            LastUpdatedDateTime   = $state.LastUpdatedDateTime
        })
    }
}

$output = @($details | Sort-Object UserPrincipalName,SkuPartNumber,AssignmentType,AssignedByGroupName)
$parent = Split-Path -Parent $ExportCsv
if ($parent) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
$output | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8

$summary = @(
    $output | Group-Object UserId | ForEach-Object {
        $rows = @($_.Group)
        [pscustomobject]@{
            DisplayName           = $rows[0].DisplayName
            UserPrincipalName     = $rows[0].UserPrincipalName
            UserId                = $rows[0].UserId
            LicenseSkuCount       = @($rows.SkuId | Sort-Object -Unique).Count
            LicenseSkus           = @($rows.SkuPartNumber | Sort-Object -Unique) -join ';'
            HasDirectAssignment   = @($rows | Where-Object AssignmentType -eq 'Direct').Count -gt 0
            HasGroupAssignment    = @($rows | Where-Object AssignmentType -eq 'Group').Count -gt 0
            AssigningGroups       = @($rows.AssignedByGroupName | Where-Object { $_ } | Sort-Object -Unique) -join ';'
        }
    } | Sort-Object UserPrincipalName
)

if ($SummaryCsv) {
    $summaryParent = Split-Path -Parent $SummaryCsv
    if ($summaryParent) { New-Item -Path $summaryParent -ItemType Directory -Force | Out-Null }
    $summary | Export-Csv -Path $SummaryCsv -NoTypeInformation -Encoding utf8
}

Write-Host ''
Write-Host "Disabled users evaluated     : $(@($users).Count)"
Write-Host "Disabled users with licenses : $(@($summary).Count)" -ForegroundColor $(if (@($summary).Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "License assignment rows      : $(@($output).Count)"
Write-Host "Detailed report              : $ExportCsv" -ForegroundColor Cyan
if ($SummaryCsv) { Write-Host "Summary report               : $SummaryCsv" -ForegroundColor Cyan }
Write-Host 'Read-only audit complete. No directory or licensing changes were made.' -ForegroundColor Green
