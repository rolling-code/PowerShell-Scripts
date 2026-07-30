#requires -Version 5.1
<#
.SYNOPSIS
Exports an inventory of Microsoft Entra application registrations and service principals.

.DESCRIPTION
Enumerates all application registration objects and enterprise application service
principals visible to the current Microsoft Graph session. The script exports separate
CSV reports plus a normalized combined inventory.

The script reuses an existing Microsoft Graph PowerShell session by default. It does not
install modules, request new consent, or disconnect a session that it did not create.
Use -ConnectIfNeeded only when an interactive connection should be attempted.

Application registrations and service principals are different directory objects. An
application registration defines an application, while a service principal represents
an application's local identity in a tenant. Consequently, their counts do not need to
match.

.PARAMETER OutputPath
Directory in which the CSV reports are created. Defaults to the script directory.

.PARAMETER TenantId
Optional tenant ID or verified tenant domain used only with -ConnectIfNeeded.

.PARAMETER ConnectIfNeeded
If no Microsoft Graph session exists, interactively connects with Application.Read.All.
Without this switch, the script stops and explains how to establish a session.

.EXAMPLE
Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome
.\list_all_applications.ps1

Reuses the current Microsoft Graph session and writes reports beside the script.

.EXAMPLE
.\list_all_applications.ps1 -OutputPath "C:\Reports"

Writes reports to C:\Reports while reusing the current Graph session.

.EXAMPLE
.\list_all_applications.ps1 -ConnectIfNeeded -TenantId "contoso.onmicrosoft.com"

Connects interactively only when no Graph session already exists.

.NOTES
Required Microsoft Graph permission: Application.Read.All or another permission that
allows both application and service-principal enumeration.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [switch]$ConnectIfNeeded
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Join-Values {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object]$Value
    )

    process {
        if ($null -eq $Value) { return '' }
        $items = @($Value) | Where-Object { $null -ne $_ -and "$_" -ne '' }
        return ($items -join ';')
    }
}

function Get-DateText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace("$Value")) { return '' }
    try { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    catch { return "$Value" }
}

function Get-GraphProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }

    $additionalProperty = $InputObject.PSObject.Properties['AdditionalProperties']
    if ($null -ne $additionalProperty -and $null -ne $additionalProperty.Value) {
        $dictionary = $additionalProperty.Value
        if ($dictionary -is [System.Collections.IDictionary]) {
            foreach ($key in $dictionary.Keys) {
                if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $dictionary[$key]
                }
            }
        }
    }

    return $null
}

function Get-VerifiedPublisherName {
    [CmdletBinding()]
    param([AllowNull()][object]$InputObject)

    $verifiedPublisher = Get-GraphProperty -InputObject $InputObject -Name 'VerifiedPublisher'
    if ($null -eq $verifiedPublisher) { return '' }

    $displayName = Get-GraphProperty -InputObject $verifiedPublisher -Name 'DisplayName'
    if ($null -ne $displayName) { return $displayName }

    if ($verifiedPublisher -is [System.Collections.IDictionary] -and $verifiedPublisher.Contains('displayName')) {
        return $verifiedPublisher['displayName']
    }

    return ''
}

$requiredCommands = @(
    'Get-MgContext',
    'Connect-MgGraph',
    'Get-MgApplication',
    'Get-MgServicePrincipal'
)

$missingCommands = @(
    foreach ($command in $requiredCommands) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { $command }
    }
)

if ($missingCommands.Count -gt 0) {
    throw "Missing Microsoft Graph PowerShell command(s): $($missingCommands -join ', '). Install the Microsoft.Graph module before running this script."
}

$context = Get-MgContext
$createdSession = $false

if ($null -eq $context) {
    if (-not $ConnectIfNeeded) {
        throw 'No active Microsoft Graph session was found. Run Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome, or rerun this script with -ConnectIfNeeded.'
    }

    $connectParameters = @{
        Scopes    = @('Application.Read.All')
        NoWelcome = $true
    }
    if ($TenantId) { $connectParameters.TenantId = $TenantId }

    Connect-MgGraph @connectParameters
    $createdSession = $true
    $context = Get-MgContext
}

if ($null -eq $context) {
    throw 'Microsoft Graph authentication did not produce an active session.'
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
}

$resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$appPath = Join-Path $resolvedOutputPath "entra-application-registrations-$timestamp.csv"
$spPath = Join-Path $resolvedOutputPath "entra-service-principals-$timestamp.csv"
$combinedPath = Join-Path $resolvedOutputPath "entra-application-inventory-$timestamp.csv"

Write-Host "Reusing Microsoft Graph session for $($context.Account)." -ForegroundColor Cyan
Write-Host "Tenant ID: $($context.TenantId) | Authentication: $($context.AuthType)" -ForegroundColor DarkGray
Write-Host 'Retrieving application registrations...' -ForegroundColor Cyan

$applications = @(Get-MgApplication -All -Property @(
    'id', 'appId', 'displayName', 'createdDateTime', 'signInAudience',
    'publisherDomain', 'verifiedPublisher', 'tags', 'disabledByMicrosoftStatus',
    'keyCredentials', 'passwordCredentials'
))

Write-Host 'Retrieving service principals...' -ForegroundColor Cyan

$servicePrincipals = @(Get-MgServicePrincipal -All -Property @(
    'id', 'appId', 'displayName', 'accountEnabled', 'servicePrincipalType',
    'signInAudience', 'appOwnerOrganizationId', 'createdDateTime',
    'publisherName', 'verifiedPublisher', 'homepage', 'replyUrls',
    'servicePrincipalNames', 'tags', 'disabledByMicrosoftStatus',
    'keyCredentials', 'passwordCredentials'
))

$appReport = @(
    foreach ($app in $applications) {
        $passwordCredentials = @(Get-GraphProperty -InputObject $app -Name 'PasswordCredentials')
        $keyCredentials = @(Get-GraphProperty -InputObject $app -Name 'KeyCredentials')

        [pscustomobject][ordered]@{
            ObjectType                = 'ApplicationRegistration'
            DisplayName               = Get-GraphProperty -InputObject $app -Name 'DisplayName'
            ApplicationClientId       = Get-GraphProperty -InputObject $app -Name 'AppId'
            ApplicationObjectId       = Get-GraphProperty -InputObject $app -Name 'Id'
            CreatedDateTimeUtc        = Get-DateText (Get-GraphProperty -InputObject $app -Name 'CreatedDateTime')
            SignInAudience            = Get-GraphProperty -InputObject $app -Name 'SignInAudience'
            PublisherDomain           = Get-GraphProperty -InputObject $app -Name 'PublisherDomain'
            VerifiedPublisher         = Get-VerifiedPublisherName -InputObject $app
            DisabledByMicrosoftStatus = Get-GraphProperty -InputObject $app -Name 'DisabledByMicrosoftStatus'
            PasswordCredentialCount   = @($passwordCredentials | Where-Object { $null -ne $_ }).Count
            KeyCredentialCount        = @($keyCredentials | Where-Object { $null -ne $_ }).Count
            Tags                      = Join-Values (Get-GraphProperty -InputObject $app -Name 'Tags')
        }
    }
)

$spReport = @(
    foreach ($sp in $servicePrincipals) {
        $passwordCredentials = @(Get-GraphProperty -InputObject $sp -Name 'PasswordCredentials')
        $keyCredentials = @(Get-GraphProperty -InputObject $sp -Name 'KeyCredentials')

        [pscustomobject][ordered]@{
            ObjectType                = 'ServicePrincipal'
            DisplayName               = Get-GraphProperty -InputObject $sp -Name 'DisplayName'
            ApplicationClientId       = Get-GraphProperty -InputObject $sp -Name 'AppId'
            ServicePrincipalObjectId  = Get-GraphProperty -InputObject $sp -Name 'Id'
            AccountEnabled            = Get-GraphProperty -InputObject $sp -Name 'AccountEnabled'
            ServicePrincipalType      = Get-GraphProperty -InputObject $sp -Name 'ServicePrincipalType'
            CreatedDateTimeUtc        = Get-DateText (Get-GraphProperty -InputObject $sp -Name 'CreatedDateTime')
            SignInAudience            = Get-GraphProperty -InputObject $sp -Name 'SignInAudience'
            AppOwnerOrganizationId    = Get-GraphProperty -InputObject $sp -Name 'AppOwnerOrganizationId'
            PublisherName             = Get-GraphProperty -InputObject $sp -Name 'PublisherName'
            VerifiedPublisher         = Get-VerifiedPublisherName -InputObject $sp
            Homepage                  = Get-GraphProperty -InputObject $sp -Name 'Homepage'
            ReplyUrls                 = Join-Values (Get-GraphProperty -InputObject $sp -Name 'ReplyUrls')
            ServicePrincipalNames     = Join-Values (Get-GraphProperty -InputObject $sp -Name 'ServicePrincipalNames')
            DisabledByMicrosoftStatus = Get-GraphProperty -InputObject $sp -Name 'DisabledByMicrosoftStatus'
            PasswordCredentialCount   = @($passwordCredentials | Where-Object { $null -ne $_ }).Count
            KeyCredentialCount        = @($keyCredentials | Where-Object { $null -ne $_ }).Count
            Tags                      = Join-Values (Get-GraphProperty -InputObject $sp -Name 'Tags')
        }
    }
)

$combinedReport = @(
    foreach ($app in $appReport) {
        [pscustomobject][ordered]@{
            ObjectType             = $app.ObjectType
            DisplayName            = $app.DisplayName
            ApplicationClientId    = $app.ApplicationClientId
            DirectoryObjectId      = $app.ApplicationObjectId
            AccountEnabled         = ''
            ServicePrincipalType   = ''
            SignInAudience         = $app.SignInAudience
            CreatedDateTimeUtc     = $app.CreatedDateTimeUtc
            Publisher              = $app.PublisherDomain
            VerifiedPublisher      = $app.VerifiedPublisher
            PasswordCredentialCount = $app.PasswordCredentialCount
            KeyCredentialCount     = $app.KeyCredentialCount
            DisabledByMicrosoftStatus = $app.DisabledByMicrosoftStatus
        }
    }
    foreach ($sp in $spReport) {
        [pscustomobject][ordered]@{
            ObjectType             = $sp.ObjectType
            DisplayName            = $sp.DisplayName
            ApplicationClientId    = $sp.ApplicationClientId
            DirectoryObjectId      = $sp.ServicePrincipalObjectId
            AccountEnabled         = $sp.AccountEnabled
            ServicePrincipalType   = $sp.ServicePrincipalType
            SignInAudience         = $sp.SignInAudience
            CreatedDateTimeUtc     = $sp.CreatedDateTimeUtc
            Publisher              = $sp.PublisherName
            VerifiedPublisher      = $sp.VerifiedPublisher
            PasswordCredentialCount = $sp.PasswordCredentialCount
            KeyCredentialCount     = $sp.KeyCredentialCount
            DisabledByMicrosoftStatus = $sp.DisabledByMicrosoftStatus
        }
    }
)

$appReport | Sort-Object DisplayName, ApplicationClientId |
    Export-Csv -LiteralPath $appPath -NoTypeInformation -Encoding UTF8
$spReport | Sort-Object DisplayName, ApplicationClientId |
    Export-Csv -LiteralPath $spPath -NoTypeInformation -Encoding UTF8
$combinedReport | Sort-Object ObjectType, DisplayName, ApplicationClientId |
    Export-Csv -LiteralPath $combinedPath -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host 'Inventory complete.' -ForegroundColor Green
Write-Host "Application registrations : $($appReport.Count)"
Write-Host "Service principals         : $($spReport.Count)"
Write-Host "Combined inventory rows    : $($combinedReport.Count)"
Write-Host "Application report         : $appPath"
Write-Host "Service principal report   : $spPath"
Write-Host "Combined report            : $combinedPath"

if ($createdSession) {
    Write-Host 'The Graph session created by this script remains connected for reuse.' -ForegroundColor DarkGray
}
