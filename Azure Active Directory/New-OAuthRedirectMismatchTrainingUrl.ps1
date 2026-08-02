<#
.SYNOPSIS
Generates a constrained OAuth URL that intentionally uses an unregistered redirect URI to demonstrate AADSTS50011.

.DESCRIPTION
Builds an authorization URL for an application the operator owns while intentionally supplying a redirect URI
that is not registered on that application. Microsoft Entra should reject the request with AADSTS50011. This safely
teaches that app display names and genuine Microsoft sign-in pages do not override redirect-URI validation.
The script does not use a Microsoft-owned client ID, acquire tokens, modify applications, open a browser, or deliver a URL.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [ValidateScript({
        $parsed = $null
        if (-not [uri]::TryCreate($_, [UriKind]::Absolute, [ref]$parsed)) { throw 'The redirect URI must be absolute.' }
        if ($parsed.Scheme -ne 'https') { throw 'The demonstration redirect URI must use HTTPS.' }
        return $true
    })]
    [string]$IntentionallyUnregisteredRedirectUri = 'https://example.invalid/not-registered',

    [switch]$CopyToClipboard,

    [Parameter(Mandatory)]
    [switch]$AcknowledgeAuthorizedTraining
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AcknowledgeAuthorizedTraining) { throw 'Authorized-training acknowledgement is required.' }

$stateBytes = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($stateBytes)
$state = [Convert]::ToBase64String($stateBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
$query = [ordered]@{
    client_id = $ClientId
    response_type = 'code'
    redirect_uri = $IntentionallyUnregisteredRedirectUri
    response_mode = 'query'
    scope = 'openid profile'
    state = $state
}
$encoded = @($query.GetEnumerator() | ForEach-Object {
    '{0}={1}' -f [uri]::EscapeDataString([string]$_.Key), [uri]::EscapeDataString([string]$_.Value)
}) -join '&'
$url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?$encoded"

[pscustomobject]@{
    Scenario = 'Intentional redirect mismatch'
    ExpectedResult = 'AADSTS50011'
    ClientOwnership = 'Operator-owned or explicitly authorized application only'
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
Write-Warning 'Expected result is redirect rejection. Do not register the demonstration redirect URI.'
