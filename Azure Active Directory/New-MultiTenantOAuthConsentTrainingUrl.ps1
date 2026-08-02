<#
.SYNOPSIS
Generates a constrained multi-tenant OAuth authorization URL for an authorized consent-screen training demonstration.

.DESCRIPTION
Builds an OAuth 2.0 authorization URL for a multi-tenant Microsoft Entra application owned by the operator.
It demonstrates that an application registered in one tenant can request sign-in or consent from users in another.
The application must already be configured for multiple organizations and the redirect URI must already be registered.
The script does not create or modify applications, open a browser, deliver the URL, exchange an authorization code,
acquire tokens, or request mail, file, directory, chat, Teams, site, calendar, write, or persistent-access scopes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [ValidateSet('organizations','common')]
    [string]$Authority = 'organizations',

    [ValidateScript({
        $parsed = $null
        if (-not [uri]::TryCreate($_, [UriKind]::Absolute, [ref]$parsed)) { throw 'RedirectUri must be absolute.' }
        if ($parsed.Scheme -eq 'https' -or ($parsed.Scheme -eq 'http' -and $parsed.IsLoopback)) { return $true }
        throw 'RedirectUri must use HTTPS or HTTP loopback.'
    })]
    [string]$RedirectUri = 'https://example.invalid/oauth-training-multitenant.html',

    [ValidateSet('openid','profile','email','User.Read')]
    [string[]]$Scopes = @('openid','profile','User.Read'),

    [switch]$CopyToClipboard,

    [Parameter(Mandatory)]
    [switch]$AcknowledgeAuthorizedTraining
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AcknowledgeAuthorizedTraining) { throw 'Authorized-training acknowledgement is required.' }

$scopesNormalized = @('openid') + @($Scopes | Where-Object { $_ -ne 'openid' })
$scopesNormalized = @($scopesNormalized | Sort-Object -Unique)
$stateBytes = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($stateBytes)
$state = [Convert]::ToBase64String($stateBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
$query = [ordered]@{
    client_id = $ClientId
    response_type = 'code'
    redirect_uri = $RedirectUri
    response_mode = 'query'
    scope = ($scopesNormalized -join ' ')
    state = $state
    prompt = 'consent'
}
$encoded = @($query.GetEnumerator() | ForEach-Object {
    '{0}={1}' -f [uri]::EscapeDataString([string]$_.Key), [uri]::EscapeDataString([string]$_.Value)
}) -join '&'
$url = "https://login.microsoftonline.com/$Authority/oauth2/v2.0/authorize?$encoded"

[pscustomobject]@{
    Scenario = 'Multi-tenant application'
    Authority = $Authority
    ClientId = $ClientId
    RedirectUri = $RedirectUri
    Scopes = $scopesNormalized -join ' '
    TokenAcquisition = 'Not implemented'
    AuthorizationUrl = $url
} | Format-List

if ($CopyToClipboard) {
    if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
        Set-Clipboard $url
        Write-Host 'URL copied.' -ForegroundColor Cyan
    } else {
        Write-Warning 'Set-Clipboard is unavailable.'
    }
}
Write-Warning 'Training URL only. No browser launch, delivery, code exchange, or token acquisition is implemented.'
