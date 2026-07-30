#requires -Version 7.0
<#
.SYNOPSIS
    Performs a controlled Microsoft Entra ROPC authentication test against one
    explicitly authorized public-client application.

.DESCRIPTION
    Sends one Resource Owner Password Credentials (ROPC) token request for a
    designated nonprivileged test account, client application, and OAuth scope.
    The script does not enumerate tenant applications, does not store a password
    in the file, and does not write access or refresh tokens to disk.

    ROPC is deprecated and incompatible with interactive MFA. Use this script
    only in an authorized test tenant or approved assessment scope.

.PARAMETER TenantId
    Microsoft Entra tenant GUID or verified tenant domain, for example:
    00000000-0000-0000-0000-000000000000 or contoso.onmicrosoft.com

.PARAMETER Username
    User principal name of a dedicated, nonprivileged test account.

.PARAMETER ClientId
    Application (client) ID of one explicitly authorized public-client app.

.PARAMETER Scope
    OAuth scope to request. The default requests Microsoft Graph delegated
    permissions already granted to the client by using .default.

.PARAMETER OutputPath
    Optional CSV path for the sanitized test result. Tokens and passwords are
    never included in the report.

.PARAMETER AcknowledgeAuthorizedTesting
    Required safety switch confirming that the test is authorized.

.EXAMPLE
    ./Test-EntraRopcControl.ps1 `
        -TenantId '00000000-0000-0000-0000-000000000000' `
        -Username 'ropc-test@contoso.onmicrosoft.com' `
        -ClientId '11111111-1111-1111-1111-111111111111' `
        -AcknowledgeAuthorizedTesting

.NOTES
    Recommended test design:
    - Use a dedicated, nonprivileged test account.
    - Use one application that is owned and approved for testing.
    - Run during an approved assessment window.
    - Review the corresponding Microsoft Entra sign-in log.
    - Rotate the test password after the assessment.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$Username,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Scope = 'https://graph.microsoft.com/.default',

    [Parameter()]
    [string]$OutputPath = (Join-Path $PWD 'EntraRopcControlTest.csv'),

    [Parameter(Mandatory)]
    [switch]$AcknowledgeAuthorizedTesting
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $AcknowledgeAuthorizedTesting) {
    throw 'Authorized-testing acknowledgement is required.'
}

Write-Warning 'ROPC is deprecated and directly handles a password. Use only an approved nonprivileged test account and application.'

$securePassword = Read-Host -Prompt "Enter the password for authorized test account $Username" -AsSecureString
$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$plainPassword = $null

$tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$timestamp = Get-Date
$correlationId = [guid]::NewGuid().Guid

try {
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)

    $body = @{
        client_id  = $ClientId
        grant_type = 'password'
        username   = $Username
        password   = $plainPassword
        scope      = $Scope
    }

    $headers = @{
        'client-request-id'        = $correlationId
        'return-client-request-id' = 'true'
    }

    try {
        $response = Invoke-RestMethod `
            -Method Post `
            -Uri $tokenEndpoint `
            -ContentType 'application/x-www-form-urlencoded' `
            -Headers $headers `
            -Body $body `
            -ErrorAction Stop

        $result = [pscustomobject]@{
            TimestampUtc       = $timestamp.ToUniversalTime().ToString('o')
            Tenant             = $TenantId
            Username           = $Username
            ClientId           = $ClientId
            Scope              = $Scope
            Outcome            = 'TokenIssued'
            HttpStatus         = 200
            EntraError         = $null
            EntraErrorCodes    = $null
            Suberror           = $null
            TraceId            = $null
            CorrelationId      = $correlationId
            MfaInterpretation  = 'The tested request completed without an interactive MFA challenge. Review Conditional Access and sign-in logs before drawing broader conclusions.'
            TokenReturned      = -not [string]::IsNullOrWhiteSpace([string]$response.access_token)
        }

        Write-Host 'TOKEN ISSUED: The authorized ROPC test returned an access token.' -ForegroundColor Red
        Write-Host 'Review the corresponding Entra sign-in log and applicable Conditional Access policies.' -ForegroundColor Yellow
    }
    catch {
        $statusCode = $null
        $responseText = $null

        if ($null -ne $_.Exception.Response) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { }
        }

        if ($null -ne $_.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($_.ErrorDetails.Message)) {
            $responseText = $_.ErrorDetails.Message
        }

        $errorPayload = $null
        if (-not [string]::IsNullOrWhiteSpace($responseText)) {
            try { $errorPayload = $responseText | ConvertFrom-Json -ErrorAction Stop } catch { }
        }

        $entraError = if ($null -ne $errorPayload) { [string]$errorPayload.error } else { 'RequestFailed' }
        $description = if ($null -ne $errorPayload) { [string]$errorPayload.error_description } else { $_.Exception.Message }
        $errorCodes = if ($null -ne $errorPayload -and $null -ne $errorPayload.error_codes) {
            @($errorPayload.error_codes) -join ';'
        }
        else {
            $null
        }
        $suberrorProperty = if ($null -ne $errorPayload) {
			$errorPayload.PSObject.Properties['suberror']
		}
		else {
			$null
		}

		$suberror = if ($null -ne $suberrorProperty) {
			[string]$suberrorProperty.Value
		}
		else {
			$null
		}
        $traceId = if ($null -ne $errorPayload -and $null -ne $errorPayload.trace_id) { [string]$errorPayload.trace_id } else { $null }
        $serverCorrelationId = if ($null -ne $errorPayload -and $null -ne $errorPayload.correlation_id) {
            [string]$errorPayload.correlation_id
        }
        else {
            $correlationId
        }

        $mfaInterpretation = if ($errorCodes -split ';' -contains '50076') {
            'Expected secure outcome for this test: MFA was required and ROPC could not satisfy the challenge.'
        }
        elseif ($errorCodes -split ';' -contains '50079') {
            'MFA enrollment or stronger authentication was required; ROPC could not complete the interactive requirement.'
        }
        else {
            'The token request failed. Review the Entra error code and sign-in log; HTTP status alone is not sufficient for classification.'
        }

        $result = [pscustomobject]@{
            TimestampUtc       = $timestamp.ToUniversalTime().ToString('o')
            Tenant             = $TenantId
            Username           = $Username
            ClientId           = $ClientId
            Scope              = $Scope
            Outcome            = 'TokenDenied'
            HttpStatus         = $statusCode
            EntraError         = $entraError
            EntraErrorCodes    = $errorCodes
            Suberror           = $suberror
            TraceId            = $traceId
            CorrelationId      = $serverCorrelationId
            MfaInterpretation  = $mfaInterpretation
            TokenReturned      = $false
        }

        if ($errorCodes -split ';' -contains '50076') {
            Write-Host 'EXPECTED: MFA was required and the ROPC request was blocked (AADSTS50076).' -ForegroundColor Green
        }
        else {
            Write-Host "TOKEN DENIED: $entraError | Error code(s): $errorCodes" -ForegroundColor Yellow
        }
        Write-Host $description -ForegroundColor DarkGray
    }

    $outputDirectory = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
    }

    $result | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8
    Write-Host "Sanitized result saved to: $OutputPath" -ForegroundColor Cyan
}
finally {
    if ($null -ne $plainPassword) {
        $plainPassword = $null
    }

    if ($passwordPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }

    Remove-Variable securePassword -ErrorAction SilentlyContinue
    Remove-Variable body -ErrorAction SilentlyContinue
    [GC]::Collect()
}
