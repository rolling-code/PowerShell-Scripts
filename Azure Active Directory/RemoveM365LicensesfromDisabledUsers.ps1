#requires -Version 5.1
<#
.SYNOPSIS
Audits disabled Microsoft Entra users and optionally removes directly assigned licenses.

.DESCRIPTION
Reuses the current Microsoft Graph PowerShell session. By default, the script performs
an audit only and exports detailed license and action reports. No license is removed
unless -Execute is explicitly supplied.

License assignment source is determined from licenseAssignmentStates.assignedByGroup.
Only directly assigned SKU IDs are eligible for removal. Group-based assignments are
reported but are never removed by this script.

.PARAMETER Execute
Enables removal of directly assigned licenses. Without this switch, the script is read-only.

.PARAMETER UserPrincipalName
Limits the run to one or more specified user principal names.

.PARAMETER ApprovedUsersCsv
Limits the run to users in a reviewed CSV containing a UserPrincipalName column.

.PARAMETER OutputPath
Directory for timestamped CSV reports. Defaults to the script directory.

.PARAMETER IncludeGuests
Includes disabled guest users. Guests are excluded by default.

.EXAMPLE
.\RemoveM365LicensesfromDisabledUsers.ps1

.EXAMPLE
.\RemoveM365LicensesfromDisabledUsers.ps1 -ApprovedUsersCsv .\approved-users.csv -Execute -WhatIf

.EXAMPLE
.\RemoveM365LicensesfromDisabledUsers.ps1 -ApprovedUsersCsv .\approved-users.csv -Execute

.NOTES
The script does not initiate authentication or request consent. License removal requires
an existing Graph session with sufficient permission and a supported Entra administrative role.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$Execute,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$UserPrincipalName,

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ApprovedUsersCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter()]
    [switch]$IncludeGuests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SafeProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }

    $additional = $InputObject.PSObject.Properties['AdditionalProperties']
    if ($null -ne $additional -and $null -ne $additional.Value) {
        foreach ($key in @($additional.Value.Keys)) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $additional.Value[$key]
            }
        }
    }

    return $null
}

function ConvertTo-SkuIdText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return ([string]$Value).Trim('{}').ToLowerInvariant()
}

$requiredCommands = @(
    'Get-MgContext',
    'Get-MgUser',
    'Get-MgSubscribedSku',
    'Set-MgUserLicense'
)

$missingCommands = @(
    foreach ($command in $requiredCommands) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { $command }
    }
)

if (@($missingCommands).Count -gt 0) {
    throw "Missing Microsoft Graph PowerShell command(s): $($missingCommands -join ', '). Install the Microsoft.Graph module before running this script."
}

$context = Get-MgContext
if ($null -eq $context) {
    throw 'No active Microsoft Graph session was found. Connect with permissions already approved for your environment, then rerun the script.'
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
}

$resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$detailPath = Join-Path $resolvedOutputPath "disabled-user-license-details-$timestamp.csv"
$summaryPath = Join-Path $resolvedOutputPath "disabled-user-license-actions-$timestamp.csv"

$approvedUpns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($upn in @($UserPrincipalName)) {
    if (-not [string]::IsNullOrWhiteSpace($upn)) { $null = $approvedUpns.Add($upn.Trim()) }
}

if ($ApprovedUsersCsv) {
    $approvedRows = @(Import-Csv -LiteralPath $ApprovedUsersCsv)
    if (@($approvedRows).Count -gt 0 -and $approvedRows[0].PSObject.Properties.Name -notcontains 'UserPrincipalName') {
        throw "The approved users CSV must contain a UserPrincipalName column: $ApprovedUsersCsv"
    }

    foreach ($row in $approvedRows) {
        if (-not [string]::IsNullOrWhiteSpace($row.UserPrincipalName)) {
            $null = $approvedUpns.Add($row.UserPrincipalName.Trim())
        }
    }
}

Write-Host "Reusing Microsoft Graph session for $($context.Account)." -ForegroundColor Cyan
Write-Host "Tenant ID: $($context.TenantId) | Authentication: $($context.AuthType)" -ForegroundColor DarkGray
Write-Host "Mode: $(if ($Execute) { 'EXECUTE' } else { 'AUDIT ONLY' })" -ForegroundColor $(if ($Execute) { 'Yellow' } else { 'Green' })

Write-Host 'Retrieving subscribed SKUs...' -ForegroundColor Cyan
$skuNameById = @{}
$subscribedSkus = @(Get-MgSubscribedSku -All -Property @('skuId', 'skuPartNumber'))
foreach ($sku in $subscribedSkus) {
    $skuId = ConvertTo-SkuIdText (Get-SafeProperty -InputObject $sku -Name 'SkuId')
    if (-not $skuId) { continue }

    $skuPartNumber = Get-SafeProperty -InputObject $sku -Name 'SkuPartNumber'
    $skuNameById[$skuId] = if ($skuPartNumber) { [string]$skuPartNumber } else { $skuId }
}

Write-Host 'Retrieving disabled users with effective license assignments...' -ForegroundColor Cyan
$userFilter = if ($IncludeGuests) {
    'accountEnabled eq false and assignedLicenses/$count ne 0'
} else {
    "accountEnabled eq false and userType eq 'Member' and assignedLicenses/`$count ne 0"
}

$disabledUsers = @(Get-MgUser -All `
    -Filter $userFilter `
    -ConsistencyLevel eventual `
    -CountVariable disabledLicensedUserCount `
    -Property @(
        'id', 'displayName', 'userPrincipalName', 'userType', 'accountEnabled',
        'assignedLicenses', 'licenseAssignmentStates'
    ))

if ($approvedUpns.Count -gt 0) {
    $disabledUsers = @($disabledUsers | Where-Object {
        $upn = [string](Get-SafeProperty -InputObject $_ -Name 'UserPrincipalName')
        $approvedUpns.Contains($upn)
    })
}

$detailRows = [System.Collections.Generic.List[object]]::new()
$summaryRows = [System.Collections.Generic.List[object]]::new()
$processed = 0
$eligibleUsers = 0
$successfulUsers = 0
$failedUsers = 0

foreach ($user in @($disabledUsers)) {
    $processed++
    if (($processed % 200) -eq 0) {
        Write-Host "Processed $processed of $(@($disabledUsers).Count) users..." -ForegroundColor DarkGray
    }

    $userId = [string](Get-SafeProperty -InputObject $user -Name 'Id')
    $upn = [string](Get-SafeProperty -InputObject $user -Name 'UserPrincipalName')
    $displayName = [string](Get-SafeProperty -InputObject $user -Name 'DisplayName')
    $userType = [string](Get-SafeProperty -InputObject $user -Name 'UserType')
    $assignmentStates = @(Get-SafeProperty -InputObject $user -Name 'LicenseAssignmentStates')
    $assignedLicenses = @(Get-SafeProperty -InputObject $user -Name 'AssignedLicenses')

    $stateBySku = @{}
    foreach ($state in $assignmentStates) {
        $stateSkuId = ConvertTo-SkuIdText (Get-SafeProperty -InputObject $state -Name 'SkuId')
        if (-not $stateSkuId) { continue }

        if (-not $stateBySku.ContainsKey($stateSkuId)) {
            $stateBySku[$stateSkuId] = [System.Collections.Generic.List[object]]::new()
        }
        $stateBySku[$stateSkuId].Add($state)
    }

    $effectiveSkuIds = @(
        @(
            foreach ($license in $assignedLicenses) {
                $id = ConvertTo-SkuIdText (Get-SafeProperty -InputObject $license -Name 'SkuId')
                if ($id) { $id }
            }
        ) | Sort-Object -Unique
    )

    $directSkuIds = [System.Collections.Generic.List[string]]::new()

    foreach ($skuId in $effectiveSkuIds) {
        $skuStates = if ($stateBySku.ContainsKey($skuId)) { @($stateBySku[$skuId]) } else { @() }
        $directStates = @($skuStates | Where-Object {
            [string]::IsNullOrWhiteSpace([string](Get-SafeProperty -InputObject $_ -Name 'AssignedByGroup'))
        })
        $groupStates = @($skuStates | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string](Get-SafeProperty -InputObject $_ -Name 'AssignedByGroup'))
        })

        $assignmentSource = if (@($directStates).Count -gt 0 -and @($groupStates).Count -gt 0) {
            'DirectAndGroup'
        } elseif (@($directStates).Count -gt 0) {
            'Direct'
        } elseif (@($groupStates).Count -gt 0) {
            'Group'
        } else {
            'Unknown'
        }

        if (@($directStates).Count -gt 0) { $directSkuIds.Add($skuId) }

        $groupIds = @(
            $groupStates | ForEach-Object { Get-SafeProperty -InputObject $_ -Name 'AssignedByGroup' } |
                Where-Object { $_ } | Sort-Object -Unique
        )
        $stateValues = @(
            $skuStates | ForEach-Object { Get-SafeProperty -InputObject $_ -Name 'State' } |
                Where-Object { $_ } | Sort-Object -Unique
        )
        $errorValues = @(
            $skuStates | ForEach-Object { Get-SafeProperty -InputObject $_ -Name 'Error' } |
                Where-Object { $_ -and $_ -ne 'None' } | Sort-Object -Unique
        )

        $detailRows.Add([pscustomobject][ordered]@{
            DisplayName        = $displayName
            UserPrincipalName  = $upn
            UserId             = $userId
            UserType           = $userType
            AccountEnabled     = $false
            SkuPartNumber      = if ($skuNameById.ContainsKey($skuId)) { $skuNameById[$skuId] } else { $skuId }
            SkuId              = $skuId
            AssignmentSource   = $assignmentSource
            EligibleForRemoval = (@($directStates).Count -gt 0)
            AssignedByGroupIds = ($groupIds -join ';')
            AssignmentState    = ($stateValues -join ';')
            AssignmentErrors   = ($errorValues -join ';')
        })
    }

    $directSkuIds = @($directSkuIds | Sort-Object -Unique)
    $action = 'AuditOnly'
    $result = 'NoChange'
    $message = ''

    if (@($directSkuIds).Count -eq 0) {
        $action = 'Skipped'
        $result = 'GroupAssignedOrUnknownOnly'
        $message = 'No directly assigned license was identified.'
    } else {
        $eligibleUsers++
        $licenseNames = @($directSkuIds | ForEach-Object {
            if ($skuNameById.ContainsKey($_)) { $skuNameById[$_] } else { $_ }
        })

        if (-not $Execute) {
            $message = "Would remove: $($licenseNames -join '; ')"
        } elseif ($PSCmdlet.ShouldProcess($upn, "Remove $(@($directSkuIds).Count) directly assigned license(s): $($licenseNames -join ', ')")) {
            $action = 'RemoveDirectLicenses'
            try {
                $null = Set-MgUserLicense `
                    -UserId $userId `
                    -AddLicenses @() `
                    -RemoveLicenses $directSkuIds `
                    -ErrorAction Stop
                $result = 'Success'
                $message = "Removed: $($licenseNames -join '; ')"
                $successfulUsers++
                Write-Host "Removed $(@($directSkuIds).Count) direct license(s) from $upn." -ForegroundColor Green
            } catch {
                $result = 'Failed'
                $message = $_.Exception.Message
                $failedUsers++
                Write-Warning "Failed to remove licenses from ${upn}: $message"
            }
        } else {
            $action = 'WhatIfOrDeclined'
            $message = "Planned removal: $($licenseNames -join '; ')"
        }
    }

    $summaryRows.Add([pscustomobject][ordered]@{
        TimestampUtc           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        DisplayName            = $displayName
        UserPrincipalName      = $upn
        UserId                 = $userId
        EffectiveLicenseCount = @($effectiveSkuIds).Count
        DirectLicenseCount    = @($directSkuIds).Count
        Action                 = $action
        Result                 = $result
        Message                = $message
    })
}

$detailRows | Sort-Object UserPrincipalName, SkuPartNumber |
    Export-Csv -LiteralPath $detailPath -NoTypeInformation -Encoding UTF8
$summaryRows | Sort-Object UserPrincipalName |
    Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host 'Processing complete.' -ForegroundColor Green
Write-Host "Disabled licensed users evaluated : $(@($disabledUsers).Count)"
Write-Host "Users with direct licenses         : $eligibleUsers"
Write-Host "Successful remediation actions    : $successfulUsers"
Write-Host "Failed remediation actions        : $failedUsers"
Write-Host "Detailed license report           : $detailPath"
Write-Host "Action summary                    : $summaryPath"

if (-not $Execute) {
    Write-Host 'Audit-only mode was used. No licenses were removed.' -ForegroundColor Green
}
