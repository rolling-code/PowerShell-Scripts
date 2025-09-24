<#
.SYNOPSIS
    Lab-safe verification of Azure built-in App ID 1b730954-1685-4b74-9bfd-dac224a7b894.
    Part 1: Acquire token and inspect scopes.
    Part 2 (optional): Use token to query Microsoft Graph for applications.

.DESCRIPTION
    This script is intended for use in a tenant where you have legitimate rights to query application objects.
    It does NOT bypass policy or escalate privileges — it simply shows what happens when you request a token
    for the Azure AD PowerShell built-in application.

    Requires: MSAL.PS module for token acquisition, Microsoft Graph PowerShell SDK for Part 2.
#>

# === Parameters ===
param(
    [string]$OrgDomain = "somedomain.net",   # Change at runtime: .\list_all_applications.ps1 -OrgDomain "yourdomain.com"
    [string]$OutputPath = "$PSScriptRoot" # Folder where CSVs will be saved
)


Write-Host "=== Script starting ===" -ForegroundColor Yellow

# ---------------------------
# Helper: Decode JWT payload
# ---------------------------
function ConvertFrom-Jwt {
    param([string]$Token)
    $parts = $Token.Split('.')
    if ($parts.Length -lt 2) { throw "Invalid JWT" }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    return $json | ConvertFrom-Json
}

# ---------------------------
# Step 1: Install modules if missing
# ---------------------------
Write-Host "Step 1: Installing required modules if missing..." -ForegroundColor Cyan
if (-not (Get-Module -ListAvailable -Name MSAL.PS)) {
    Install-Module MSAL.PS -Scope CurrentUser -Force
}
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# ---------------------------
# Step 2: Import modules
# ---------------------------
Write-Host "Step 2: Importing modules..." -ForegroundColor Cyan
Import-Module MSAL.PS
Import-Module Microsoft.Graph

# ---------------------------
# Step 3: Set IDs
# ---------------------------
$ClientId = "1b730954-1685-4b74-9bfd-dac224a7b894"
Write-Host "Step 3: Using built-in Azure AD PowerShell App ID: $ClientId" -ForegroundColor Cyan

# ---------------------------
# Step 4: Acquire token interactively
# ---------------------------
Write-Host "Step 4: Authenticating to Azure AD with your account..." -ForegroundColor Cyan
$TokenResponse = Get-MsalToken -ClientId $ClientId -TenantId "common" -Interactive

# ---------------------------
# Step 5: Verify token
# ---------------------------
Write-Host "Step 5: Verifying token..." -ForegroundColor Cyan
if (-not $TokenResponse.AccessToken -or $TokenResponse.AccessToken.Length -lt 100) {
    throw "No valid JWT returned — check authentication."
}

# ---------------------------
# Step 6: Decode and display token info
# ---------------------------
Write-Host "Step 6: Decoding token..." -ForegroundColor Cyan
$decoded = ConvertFrom-Jwt $TokenResponse.AccessToken
Write-Host "Audience:" $decoded.aud -ForegroundColor Green
Write-Host "Scopes:" ($decoded.scp -join ", ") -ForegroundColor Green

# ---------------------------
# Part 2: Optional Graph query
# ---------------------------
Write-Host "`n=== Optional Part 2: Query Microsoft Graph ===" -ForegroundColor Yellow
Write-Host "Only run this in a tenant where you have rights to list applications." -ForegroundColor Magenta

try {
    $secureToken = ConvertTo-SecureString $TokenResponse.AccessToken -AsPlainText -Force
    Connect-MgGraph -AccessToken $secureToken
    Write-Host "Connected to Microsoft Graph." -ForegroundColor Green

    Write-Host "Attempting to list applications..." -ForegroundColor Cyan
    $apps = Get-MgApplication -All
    Write-Host ("Retrieved {0} applications." -f $apps.Count) -ForegroundColor Green
	
	Write-Host "Resolving Microsoft Graph permission GUIDs..." -ForegroundColor Cyan
	$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
	$permissionMap = @{}
	foreach ($perm in $graphSP.Oauth2PermissionScopes) {
		$permissionMap[$perm.Id] = [PSCustomObject]@{
			PermissionName = $perm.Value
			Description    = $perm.AdminConsentDisplayName
		}
	}




	Write-Host "`n=== Filtering results for actionable insights ===" -ForegroundColor Yellow

	# 1. Enterprise applications
	$enterpriseApps = $apps | Where-Object { $_.AppId -and $_.AppId -ne $ClientId -and $_.PublisherDomain -ne $null -and $_.PublisherDomain -notmatch $OrgDomain }
	Write-Host ("Enterprise apps: {0}" -f $enterpriseApps.Count) -ForegroundColor Cyan
	$enterpriseApps | Select-Object DisplayName, AppId, PublisherDomain |
		Export-Csv -Path (Join-Path $OutputPath "EnterpriseApps.csv") -NoTypeInformation

	# 2. Owned app registrations
	$ownedApps = $apps | Where-Object { $_.PublisherDomain -match $OrgDomain }
	Write-Host ("Owned app registrations: {0}" -f $ownedApps.Count) -ForegroundColor Cyan
	$ownedApps | Select-Object DisplayName, AppId, PublisherDomain |
		Export-Csv -Path (Join-Path $OutputPath "OwnedApps.csv") -NoTypeInformation

	# 3. Privileged apps
	$privilegedApps = $apps | Where-Object {
		$_.DisplayName -match "admin|administrator|privileged|service" -or
		($_.RequiredResourceAccess.ResourceAppId -contains "00000003-0000-0000-c000-000000000000")
	}
	Write-Host ("Privileged apps: {0}" -f $privilegedApps.Count) -ForegroundColor Cyan
	$privilegedApps | Select-Object DisplayName, AppId, PublisherDomain |
		Export-Csv -Path (Join-Path $OutputPath "PrivilegedApps.csv") -NoTypeInformation

	# --- Build Scope Report with resolved names ---
	$scopeReport = foreach ($app in $apps) {
		foreach ($access in $app.RequiredResourceAccess) {
			foreach ($scope in $access.ResourceAccess) {
				$resolved = $permissionMap[$scope.Id]
				[PSCustomObject]@{
					AppDisplayName  = $app.DisplayName
					AppId           = $app.AppId
					PublisherDomain = $app.PublisherDomain
					ResourceAppId   = $access.ResourceAppId
					ScopeId         = $scope.Id
					ScopeType       = $scope.Type
					PermissionName  = if ($resolved) { $resolved.PermissionName } else { "Unknown" }
					Description     = if ($resolved) { $resolved.Description } else { "" }
				}
			}
		}
	}

	# --- Export to CSV ---
	$scopeReport | Export-Csv -Path (Join-Path $OutputPath "ScopeBreakdown.csv") -NoTypeInformation
	Write-Host "ScopeBreakdown.csv saved with resolved permission names." -ForegroundColor Green






} catch {
    Write-Warning "Graph query failed: $($_.Exception.Message)"
} finally {
    Disconnect-MgGraph
    Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan
}

Write-Host "=== Script complete ===" -ForegroundColor Yellow