
<#
Scenario 2 – Spoofed Microsoft app (intentional error)

This script builds an OAuth URL using a Microsoft-owned client ID to demonstrate that a trusted app name
is NOT enough. The flow breaks after sign-in with AADSTS50011 because the redirect URI is not one of the
official URIs registered for that Microsoft app.

Prerequisites:
- GitHub Pages enabled; 'docs/index.html' should exist for your base landing page.
- No app registration changes are possible for Microsoft-owned client IDs.

Consistency CLI (no app create here; demonstration only):
1) TODO Confirm GitHub Pages is serving your landing page:
   https://rolling-code.github.io/PowerShell-Scripts/

2) Run this script and open the URL. Observe:
   - Microsoft login and trusted app name
   - Then AADSTS50011 redirect mismatch (by design)
#>

[CmdletBinding()]
param(
    [string] $RedirectUri = "https://rolling-code.github.io/PowerShell-Scripts/",        # TODO MUST exist in GitHub /docs
    [string] $ClientId    = "00000002-0000-0ff1-ce00-000000000000",                      # Exchange Online public appId
    [string] $Scope       = "openid profile email"
)

# ---- include helper (guarded) ----
. .\helper_scopes.ps1

# Guard: skip scope configuration for Microsoft-owned client IDs (helper detects & warns)
scope_declaration_function -AppId $ClientId | Out-Null

function Encode([string] $s) { [System.Uri]::EscapeDataString($s) }

$encRedirect = Encode $RedirectUri
$encScope    = Encode $Scope
$state       = "sim-" + [Guid]::NewGuid().ToString()

# Public Microsoft app => /common authority
$base = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

$authUrl = "$base" +
           "?client_id=$ClientId" +
           "&response_type=code" +
           "&redirect_uri=$encRedirect" +
           "&scope=$encScope" +
           "&state=$state"

Write-Host ([Environment]::NewLine + "--- OAuth URL (Spoof Microsoft App; expect AADSTS50011) ---") -ForegroundColor Green
Write-Host $authUrl -ForegroundColor Yellow

try {
    $authUrl | clip
    Write-Host ([Environment]::NewLine + "(Copied to clipboard.)") -ForegroundColor Cyan
} catch {
    Write-Verbose ('Clipboard copy failed: ' + $_)
}
