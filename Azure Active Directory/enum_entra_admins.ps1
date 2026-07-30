#requires -Version 7.0
<#
.SYNOPSIS
Exports users from Microsoft Entra groups whose display names match an administrator-like pattern.

.DESCRIPTION
Finds Microsoft Entra groups whose display names match a configurable regular expression and
exports all direct and nested user members. The default pattern matches the word
"administrator" case-insensitively. This is a naming-based discovery aid and does not prove
that a matching group grants privileged access.

.PARAMETER GroupNamePattern
Regular expression applied to group display names.

.PARAMETER OutputPath
CSV report path.

.EXAMPLE
./enum_entra_admins.ps1

.EXAMPLE
./enum_entra_admins.ps1 -GroupNamePattern '(?i)administrator|privileged admin'
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GroupNamePattern = '(?i)administrator',

    [Parameter()]
    [string]$OutputPath = (Join-Path $PWD 'AdminLikeAccounts_Report.csv')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($commandName in @('Connect-MgGraph','Get-MgContext','Get-MgGroup','Get-MgGroupTransitiveMemberAsUser')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command '$commandName' was not found. Install Microsoft.Graph.Authentication and Microsoft.Graph.Groups."
    }
}

try { [void][regex]::new($GroupNamePattern) }
catch { throw "GroupNamePattern is not a valid regular expression: $($_.Exception.Message)" }

$requiredScopes = @('GroupMember.Read.All','User.Read.All')
$context = Get-MgContext
$mustConnect = $null -eq $context
if (-not $mustConnect) {
    foreach ($scope in $requiredScopes) {
        if ($scope -notin @($context.Scopes)) { $mustConnect = $true; break }
    }
}
if ($mustConnect) {
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome | Out-Null
}

$groups = @(
    Get-MgGroup -All -Property Id,DisplayName,SecurityEnabled,MailEnabled |
        Where-Object { [string]$_.DisplayName -match $GroupNamePattern } |
        Sort-Object DisplayName
)

$results = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

foreach ($group in $groups) {
    Write-Host "Enumerating: $($group.DisplayName)" -ForegroundColor DarkGray
    try {
        $users = @(
            Get-MgGroupTransitiveMemberAsUser -GroupId $group.Id -All `
                -Property Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,OnPremisesSamAccountName,OnPremisesSyncEnabled `
                -ErrorAction Stop
        )
        foreach ($user in $users) {
            $results.Add([pscustomobject]@{
                GroupDisplayName         = $group.DisplayName
                GroupId                  = $group.Id
                GroupSecurityEnabled     = $group.SecurityEnabled
                GroupMailEnabled         = $group.MailEnabled
                MemberObjectType         = 'User'
                MemberDisplayName        = $user.DisplayName
                MemberId                 = $user.Id
                MemberUPNorAppId          = $user.UserPrincipalName
                MemberMail               = $user.Mail
                EntraAccountEnabled      = $user.AccountEnabled
                UserType                 = $user.UserType
                OnPremisesSamAccountName = $user.OnPremisesSamAccountName
                OnPremisesSyncEnabled    = $user.OnPremisesSyncEnabled
                MembershipResolution     = 'Transitive'
            })
        }
    }
    catch {
        $errors.Add([pscustomobject]@{
            GroupDisplayName = $group.DisplayName
            GroupId = $group.Id
            Error = $_.Exception.Message
        })
    }
}

$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
$results | Sort-Object GroupDisplayName,MemberDisplayName,MemberUPNorAppId |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8

Write-Host "Matching groups: $($groups.Count)"
Write-Host "Membership rows: $($results.Count)"
Write-Host "Errors: $($errors.Count)"
Write-Host "Report: $OutputPath" -ForegroundColor Cyan
if ($results.Count -gt 0) {
    $results | Select-Object GroupDisplayName,MemberDisplayName,MemberUPNorAppId,EntraAccountEnabled |
        Format-Table -AutoSize -Wrap
}
if ($errors.Count -gt 0) { $errors | Format-Table -AutoSize -Wrap }
