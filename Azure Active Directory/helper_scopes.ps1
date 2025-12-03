
<#
helper_scopes.ps1

Configures Microsoft Graph delegated scopes on an app registration so the consent prompt
shows the same permissions the OAuth URL requests.

Prereqs:
- Azure CLI installed and logged in (az login).
- AppId must be YOUR app's client ID (not a Microsoft-owned client ID).
#>

function scope_declaration_function {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $AppId,                       # TODO 

        [Parameter(Mandatory = $false)]
        [switch] $IncludeMailAndFiles,         # add Mail.Read & Files.Read

        [Parameter(Mandatory = $false)]
        [switch] $UseTempFile                  # fallback: write JSON to temp file and pass by path
    )

    # Microsoft Graph resource app ID (fixed)
    $graphAppId = "00000003-0000-0000-c000-000000000000"

    # Guard: refuse Microsoft-owned client IDs (we can't modify those anyway)
    if ($AppId -match '^(00000002-0000-0ff1-ce00-000000000000|1fec8e78-bce4-4aaf-ab1b-5451d15019d1)$') {
        Write-Warning "AppId '$AppId' looks like a Microsoft-owned client ID. Skipping scope configuration."
        return
    }

    # Delegated scope GUIDs
    $UserRead  = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read
    $MailRead  = "570282fd-fa5c-430d-a7fd-fc8dc98a9dca" # Mail.Read
    $FilesRead = "df85f4d6-205c-4ac5-a5ea-6bf408dba283" # Files.Read

    # Build the resourceAccess array
    $resourceAccess = @(
        @{ id = $UserRead;  type = "Scope" }
    )

    if ($IncludeMailAndFiles) {
        $resourceAccess += @{ id = $MailRead;  type = "Scope" }
        $resourceAccess += @{ id = $FilesRead; type = "Scope" }
    }

    # Full payload (array of one item)
    $payload = @(
        @{
            resourceAppId  = $graphAppId
            resourceAccess = $resourceAccess
        }
    )

    # Serialize to compact JSON (no comments, no line breaks)
    $json = $payload | ConvertTo-Json -Depth 6 -Compress

    Write-Host "Applying required resource access to appId $AppId ..." -ForegroundColor Cyan

    # Try direct pass first
    $result = az ad app update --id $AppId --required-resource-access $json 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Direct JSON pass failed; retrying with a temp file..."
        # Fallback: write to temp file and pass by path (quoted string so PowerShell doesn't treat '@' specially)
        $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "reqresaccess.$([Guid]::NewGuid().ToString()).json")
        Set-Content -Path $tmp -Value $json -Encoding UTF8
        $result = az ad app update --id $AppId --required-resource-access "@$tmp" 2>&1
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to update scopes. Azure CLI returned:`n$result"
    } else {
        Write-Host "Scopes updated successfully." -ForegroundColor Green
    }
}
