#requires -Version 7.0
<#
.SYNOPSIS
Checks accounts from any CSV against Microsoft Entra ID and reports disabled users.

.DESCRIPTION
Reads a CSV, identifies the column containing a user principal name or Entra object ID,
queries Microsoft Graph, and exports accounts whose Entra accountEnabled property is false.
The script requires internet access to Microsoft Graph but does not require a corporate
network, VPN, domain controller, RSAT, or the ActiveDirectory module.

.PARAMETER CsvPath
Input CSV path.

.PARAMETER IdentityColumn
Column containing a user principal name or Entra user object ID. If omitted, the script
auto-detects a common column name.

.PARAMETER OutputPath
CSV path for disabled Entra accounts.

.PARAMETER FullReportPath
Optional path for all lookup results, including enabled, disabled, not found, and errors.

.EXAMPLE
./find_disabled_accounts.ps1 -CsvPath ./accounts.csv

.EXAMPLE
./find_disabled_accounts.ps1 -CsvPath ./accounts.csv -IdentityColumn UserPrincipalName `
    -OutputPath ./DisabledAccounts_Report.csv -FullReportPath ./AccountLookup_FullReport.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter()]
    [string]$IdentityColumn,

    [Parameter()]
    [string]$OutputPath = (Join-Path $PWD 'DisabledAccounts_Report.csv'),

    [Parameter()]
    [string]$FullReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($commandName in @('Connect-MgGraph','Get-MgContext','Get-MgUser')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command '$commandName' was not found. Install Microsoft.Graph.Authentication and Microsoft.Graph.Users."
    }
}

$rows = @(Import-Csv -Path $CsvPath)
if ($rows.Count -eq 0) { throw "The input CSV contains no rows: $CsvPath" }

$columns = @($rows[0].PSObject.Properties.Name)
if ([string]::IsNullOrWhiteSpace($IdentityColumn)) {
    $candidateColumns = @(
        'UserPrincipalName','UPN','MemberUPNorAppId','MemberUserPrincipalName',
        'Email','Mail','UserEmail','Account','Username','UserId','Id','ObjectId'
    )
    $IdentityColumn = $candidateColumns | Where-Object { $_ -in $columns } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($IdentityColumn)) {
        throw "Could not auto-detect an identity column. Available columns: $($columns -join ', '). Use -IdentityColumn."
    }
}
elseif ($IdentityColumn -notin $columns) {
    throw "Identity column '$IdentityColumn' was not found. Available columns: $($columns -join ', ')."
}

$requiredScopes = @('User.Read.All')
$context = Get-MgContext
$mustConnect = $null -eq $context -or 'User.Read.All' -notin @($context.Scopes)
if ($mustConnect) { Connect-MgGraph -Scopes $requiredScopes -NoWelcome | Out-Null }

$identities = @(
    $rows | ForEach-Object { [string]$_.PSObject.Properties[$IdentityColumn].Value } |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
)

$results = [System.Collections.Generic.List[object]]::new()
foreach ($identity in $identities) {
    try {
        $user = Get-MgUser -UserId $identity -Property Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,OnPremisesSyncEnabled,OnPremisesSamAccountName -ErrorAction Stop
        $results.Add([pscustomobject]@{
            InputIdentity             = $identity
            FoundInEntra              = $true
            DisplayName               = $user.DisplayName
            UserPrincipalName         = $user.UserPrincipalName
            Mail                      = $user.Mail
            EntraObjectId             = $user.Id
            AccountEnabled            = $user.AccountEnabled
            UserType                  = $user.UserType
            OnPremisesSyncEnabled     = $user.OnPremisesSyncEnabled
            OnPremisesSamAccountName  = $user.OnPremisesSamAccountName
            Status                    = if ($user.AccountEnabled -eq $false) { 'Disabled' } else { 'Enabled' }
            Error                     = $null
        })
    }
    catch {
        $results.Add([pscustomobject]@{
            InputIdentity             = $identity
            FoundInEntra              = $false
            DisplayName               = $null
            UserPrincipalName         = $null
            Mail                      = $null
            EntraObjectId             = $null
            AccountEnabled            = $null
            UserType                  = $null
            OnPremisesSyncEnabled     = $null
            OnPremisesSamAccountName  = $null
            Status                    = 'NotFoundOrLookupError'
            Error                     = $_.Exception.Message
        })
    }
}

$disabled = @($results | Where-Object { $_.FoundInEntra -eq $true -and $_.AccountEnabled -eq $false })
$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
$disabled | Sort-Object DisplayName,UserPrincipalName |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8

if (-not [string]::IsNullOrWhiteSpace($FullReportPath)) {
    $fullParent = Split-Path -Parent $FullReportPath
    if ($fullParent) { New-Item -Path $fullParent -ItemType Directory -Force | Out-Null }
    $results | Sort-Object Status,DisplayName,InputIdentity |
        Export-Csv -Path $FullReportPath -NoTypeInformation -Encoding utf8
}

Write-Host "Identity column: $IdentityColumn"
Write-Host "Unique identities checked: $($identities.Count)"
Write-Host "Found in Entra: $(@($results | Where-Object FoundInEntra -eq $true).Count)"
Write-Host "Disabled in Entra: $($disabled.Count)" -ForegroundColor $(if ($disabled.Count) { 'Yellow' } else { 'Green' })
Write-Host "Not found or error: $(@($results | Where-Object FoundInEntra -eq $false).Count)"
Write-Host "Disabled report: $OutputPath" -ForegroundColor Cyan
if ($FullReportPath) { Write-Host "Full report: $FullReportPath" -ForegroundColor Cyan }
if ($disabled.Count -gt 0) {
    $disabled | Select-Object DisplayName,UserPrincipalName,Mail,UserType,OnPremisesSyncEnabled |
        Format-Table -AutoSize -Wrap
}
