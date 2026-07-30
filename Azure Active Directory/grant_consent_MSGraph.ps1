#requires -Version 7.0
<#
.SYNOPSIS
Audits Microsoft Entra delegated OAuth consent grants without modifying the tenant.

.DESCRIPTION
Performs a read-only review of delegated permission grants for a specified client
application, user, or both. The script resolves client and resource service
principals, validates granted scope names against the resource API, identifies
user-specific versus tenant-wide consent, and exports structured CSV evidence.

The script does not create applications, service principals, consent grants,
app-role assignments, access tokens, or refresh tokens.

.PARAMETER ClientAppId
Optional application (client) ID used to limit results to one client application.

.PARAMETER UserPrincipalName
Optional Microsoft Entra user principal name used to limit results to grants made
for one user. Tenant-wide grants are excluded when this filter is specified unless
-IncludeTenantWide is also supplied.

.PARAMETER IncludeTenantWide
When UserPrincipalName is specified, also includes grants whose ConsentType is
AllPrincipals.

.PARAMETER OutputCsv
Path for the CSV report.

.EXAMPLE
./Get-EntraDelegatedConsentGrantAudit.ps1 -ClientAppId '11111111-1111-1111-1111-111111111111'

.EXAMPLE
./Get-EntraDelegatedConsentGrantAudit.ps1 -UserPrincipalName 'alice@contoso.com' -IncludeTenantWide

.EXAMPLE
./Get-EntraDelegatedConsentGrantAudit.ps1 `
    -ClientAppId '11111111-1111-1111-1111-111111111111' `
    -UserPrincipalName 'alice@contoso.com' `
    -OutputCsv ./delegated-consent-audit.csv

.NOTES
Required delegated Microsoft Graph scopes:
- DelegatedPermissionGrant.Read.All
- Application.Read.All
- User.Read.All, only when UserPrincipalName is used

The signed-in administrator must also hold an appropriate Microsoft Entra role.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientAppId,

    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$UserPrincipalName,

    [Parameter()]
    [switch]$IncludeTenantWide,

    [Parameter()]
    [string]$OutputCsv = (Join-Path $PWD 'EntraDelegatedConsentGrantAudit.csv')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredCommands = @(
    'Connect-MgGraph',
    'Get-MgContext',
    'Get-MgServicePrincipal',
    'Get-MgOauth2PermissionGrant'
)

if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $requiredCommands += 'Get-MgUser'
}

foreach ($commandName in $requiredCommands) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command '$commandName' was not found. Install Microsoft.Graph.Authentication, Microsoft.Graph.Applications, and Microsoft.Graph.Users."
    }
}

$requiredScopes = [System.Collections.Generic.List[string]]::new()
$requiredScopes.Add('DelegatedPermissionGrant.Read.All')
$requiredScopes.Add('Application.Read.All')
if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $requiredScopes.Add('User.Read.All')
}

$context = Get-MgContext
$mustConnect = $null -eq $context
if (-not $mustConnect) {
    foreach ($scope in $requiredScopes) {
        if ($scope -notin @($context.Scopes)) {
            $mustConnect = $true
            break
        }
    }
}

if ($mustConnect) {
    Write-Host 'Connecting to Microsoft Graph with read-only scopes...' -ForegroundColor Cyan
    Connect-MgGraph -Scopes $requiredScopes.ToArray() -NoWelcome | Out-Null
}

$user = $null
if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $user = Get-MgUser -UserId $UserPrincipalName -Property Id,DisplayName,UserPrincipalName -ErrorAction Stop
    Write-Host "User filter: $($user.DisplayName) <$($user.UserPrincipalName)>" -ForegroundColor DarkGray
}

$clientServicePrincipal = $null
if (-not [string]::IsNullOrWhiteSpace($ClientAppId)) {
    $escapedClientAppId = $ClientAppId.Replace("'", "''")
    $clientMatches = @(Get-MgServicePrincipal -Filter "appId eq '$escapedClientAppId'" -All -Property Id,AppId,DisplayName,PublisherName,ServicePrincipalType)

    if ($clientMatches.Count -eq 0) {
        throw "No service principal was found for client application ID '$ClientAppId' in the connected tenant."
    }
    if ($clientMatches.Count -gt 1) {
        throw "Multiple service principals were returned for client application ID '$ClientAppId'."
    }

    $clientServicePrincipal = $clientMatches[0]
    Write-Host "Client filter: $($clientServicePrincipal.DisplayName) <$ClientAppId>" -ForegroundColor DarkGray
}

$allServicePrincipals = @(Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,PublisherName,Oauth2PermissionScopes,ServicePrincipalType)
$servicePrincipalById = @{}
foreach ($servicePrincipal in $allServicePrincipals) {
    $servicePrincipalById[[string]$servicePrincipal.Id] = $servicePrincipal
}

$grants = @(Get-MgOauth2PermissionGrant -All)
$filteredGrants = @(
    foreach ($grant in $grants) {
        if ($null -ne $clientServicePrincipal -and [string]$grant.ClientId -ne [string]$clientServicePrincipal.Id) {
            continue
        }

        if ($null -ne $user) {
            $isUserGrant = $grant.ConsentType -eq 'Principal' -and [string]$grant.PrincipalId -eq [string]$user.Id
            $isTenantWide = $IncludeTenantWide -and $grant.ConsentType -eq 'AllPrincipals'
            if (-not $isUserGrant -and -not $isTenantWide) {
                continue
            }
        }

        $grant
    }
)

$results = [System.Collections.Generic.List[object]]::new()

foreach ($grant in $filteredGrants) {
    $clientSp = $servicePrincipalById[[string]$grant.ClientId]
    $resourceSp = $servicePrincipalById[[string]$grant.ResourceId]

    $grantedScopes = @(
        ([string]$grant.Scope -split '\s+') |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )

    $definedScopes = @{}
    if ($null -ne $resourceSp) {
        foreach ($scopeDefinition in @($resourceSp.Oauth2PermissionScopes)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$scopeDefinition.Value)) {
                $definedScopes[[string]$scopeDefinition.Value] = $scopeDefinition
            }
        }
    }

    $unknownScopes = @($grantedScopes | Where-Object { -not $definedScopes.ContainsKey($_) })
    $adminConsentScopes = @(
        foreach ($scopeName in $grantedScopes) {
            if ($definedScopes.ContainsKey($scopeName)) {
                $definition = $definedScopes[$scopeName]
                if ([string]$definition.Type -eq 'Admin') {
                    $scopeName
                }
            }
        }
    )

    $riskFlags = [System.Collections.Generic.List[string]]::new()
    if ($grant.ConsentType -eq 'AllPrincipals') {
        $riskFlags.Add('TenantWideConsent')
    }
    if ($adminConsentScopes.Count -gt 0) {
        $riskFlags.Add('ContainsAdminConsentScope')
    }
    if ($unknownScopes.Count -gt 0) {
        $riskFlags.Add('UnknownOrRetiredScope')
    }
    if ($null -eq $clientSp) {
        $riskFlags.Add('ClientServicePrincipalNotResolved')
    }
    if ($null -eq $resourceSp) {
        $riskFlags.Add('ResourceServicePrincipalNotResolved')
    }

    $results.Add([pscustomobject]@{
        GrantId                      = $grant.Id
        ConsentType                 = $grant.ConsentType
        PrincipalId                 = $grant.PrincipalId
        IsRequestedUser             = $null -ne $user -and [string]$grant.PrincipalId -eq [string]$user.Id
        ClientServicePrincipalId     = $grant.ClientId
        ClientAppId                  = if ($null -ne $clientSp) { $clientSp.AppId } else { $null }
        ClientDisplayName            = if ($null -ne $clientSp) { $clientSp.DisplayName } else { $null }
        ClientPublisher              = if ($null -ne $clientSp) { $clientSp.PublisherName } else { $null }
        ResourceServicePrincipalId   = $grant.ResourceId
        ResourceAppId                = if ($null -ne $resourceSp) { $resourceSp.AppId } else { $null }
        ResourceDisplayName          = if ($null -ne $resourceSp) { $resourceSp.DisplayName } else { $null }
        GrantedScopes                = $grantedScopes -join ' '
        GrantedScopeCount            = $grantedScopes.Count
        AdminConsentScopes           = $adminConsentScopes -join ' '
        UnknownOrRetiredScopes       = $unknownScopes -join ' '
        RiskFlags                    = $riskFlags -join ';'
    })
}

$parentDirectory = Split-Path -Parent $OutputCsv
if (-not [string]::IsNullOrWhiteSpace($parentDirectory)) {
    New-Item -Path $parentDirectory -ItemType Directory -Force | Out-Null
}

$results |
    Sort-Object ConsentType, ClientDisplayName, ResourceDisplayName |
    Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding utf8

Write-Host ''
Write-Host '=== Microsoft Entra Delegated Consent Grant Audit ===' -ForegroundColor Cyan
Write-Host "Grants reviewed               : $($results.Count)"
Write-Host "Tenant-wide grants            : $(@($results | Where-Object ConsentType -eq 'AllPrincipals').Count)"
Write-Host "User-specific grants          : $(@($results | Where-Object ConsentType -eq 'Principal').Count)"
Write-Host "Grants with risk flags        : $(@($results | Where-Object { -not [string]::IsNullOrWhiteSpace($_.RiskFlags) }).Count)"
Write-Host "CSV report                    : $OutputCsv" -ForegroundColor Cyan
Write-Host ''

if ($results.Count -gt 0) {
    $results |
        Select-Object ClientDisplayName, ResourceDisplayName, ConsentType, GrantedScopeCount, RiskFlags |
        Format-Table -AutoSize -Wrap
}
else {
    Write-Host 'No delegated permission grants matched the supplied filters.' -ForegroundColor Green
}

Write-Host ''
Write-Host 'Read-only audit complete. No applications, consent grants, assignments, or tokens were created or modified.' -ForegroundColor Green
