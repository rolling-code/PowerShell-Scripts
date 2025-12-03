
<#
Scenario 1 – Org-only SAT (working)

This script generates a tenant-specific OAuth URL for a single-tenant app (AzureADMyOrg) and redirects
to your GitHub Pages training page (success.html). The goal is to show how legit Microsoft login + app
names can mislead users, and to teach verification of publisher and permissions.

Prerequisites, TODO:
- GitHub Pages enabled for https://rolling-code.github.io/PowerShell-Scripts/
- The file 'docs/success.html' MUST exist in your repo (served by Pages).
- Azure CLI installed and logged in (az login).
- Your app must be registered in YOUR org (AzureADMyOrg) and have the redirect URI(s) added.

Consistency CLI (run once to set up the app):
1) Login to Azure
   az login
   # Authenticate to Azure CLI in the org where the app will live

2) Create the app registration (captures appId)
   az ad app create `
     --display-name "TODO Security Portal" `    # Neutral name; avoid 'Microsoft', 'Teams', etc.
     --sign-in-audience AzureADMyOrg `
     --web-redirect-uris "https://rolling-code.github.io/PowerShell-Scripts/success.html" `
     --enable-id-token-issuance true
   # Creates the app and enables ID tokens
   # Save the returned "appId" (client ID) and your tenant ID/domain

3) Create the service principal
   az ad sp create --id <APP_ID>   # Use your appId here
   # Links the app to your tenant so users can sign in

4) Declare Graph delegated scopes (User.Read, etc.)
   # We do this programmatically by calling scope_declaration_function() below
   # Ensures the consent screen shows the same permissions as requested in the URL

5) (Optional) Add another redirect URI if desired
   az ad app update `
     --id <APP_ID> `               # Use your appId here
     --web-redirect-uris "https://rolling-code.github.io/PowerShell-Scripts/success.html" `
                         "https://rolling-code.github.io/PowerShell-Scripts/"
   # Keep URIs synchronized with your GitHub Pages files

6) Run this script to generate the URL and test in a browser
#>

[CmdletBinding()]
param(
    [string] $RedirectUri = "https://rolling-code.github.io/PowerShell-Scripts/success.html",  # TODO MUST exist in GitHub /docs
    [string] $ClientId    = "TODO",                            # TODO Use YOUR appId here (from Step 2)
    [string] $Tenant      = "TODO",                            # TODO or "acme.onmicrosoft.com"
    [string] $Scope       = "openid profile email User.Read"
)

# ---- include helper ----
. .\helper_scopes.ps1

# Ensure app's required resource access matches scopes requested
# Fails if not az logged in, fine if already done. 
# Presumable if you created the app for this URL you were logged in or are logged in.
scope_declaration_function -AppId $ClientId -IncludeMailAndFiles  # (optional) add Mail.Read + Files.Read

function Encode([string] $s) { [System.Uri]::EscapeDataString($s) }

# Exact match is required: redirect in URL must equal the registered URI (including path)
$encRedirect = Encode $RedirectUri
$encScope    = Encode $Scope
$state       = "sim-" + [Guid]::NewGuid().ToString()

# Single-tenant app => use tenant-specific authority
$base = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize"

$authUrl = "$base" +
           "?client_id=$ClientId" +
           "&response_type=code" +
           "&redirect_uri=$encRedirect" +
           "&scope=$encScope" +
           "&state=$state"

Write-Host ([Environment]::NewLine + "--- OAuth Simulation URL (Org-only) ---") -ForegroundColor Green
Write-Host $authUrl -ForegroundColor Yellow

try {
    $authUrl | clip
    Write-Host ([Environment]::NewLine + "(Copied to clipboard.)") -ForegroundColor Cyan
} catch {
    Write-Verbose ('Clipboard copy failed: ' + $_)
}
