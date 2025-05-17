# Replace with actual values
# dsregcmd /status does the job
#
# Run as so: & "C:\Users\mcontestabile\foobar\get_az_token.ps1" 
# if running script from another folder.
#
# If any of the calls using the Resource Owner Password Credentials (ROPC) flow succeed and return an access token, that strongly suggests that:
#
# MFA is not enforced for that user or app.
# The app registration is configured to allow public clients.
# The user account is not blocked by Conditional Access policies that would prevent password-based login.
#
$tenantId = "???"
$username = "???"
$password = "???"
$VerbosePreference = "Continue" # Enable verbose output for debugging
$ErrorActionPreference = "Continue" #prevents non-fatal errors from halting the script.

# Define Token Endpoint
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Get all client IDs using Azure CLI
$clientIds = az ad app list --all --query "[].appId" --output tsv

# Convert output into an array
$clientIdList = $clientIds -split "`n"


# Loop through each Client ID and get the access token
foreach ($clientId in $clientIdList) {
    Write-Output "Fetching token for Client ID: $clientId"

    # Create the body for the authentication request
    $body = @{
        client_id = $clientId
        scope = "https://management.azure.com/.default"
        grant_type = "password"
        username = $username
        password = $password
    }

    # Send request to obtain access token
    try {
		Write-Host "Sending request to: $tokenUrl" -ForegroundColor Cyan
		Write-Host "Request Body: $($body | Out-String)" -ForegroundColor Magenta
        $response = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
		Write-Host "Raw API Response:" -ForegroundColor Blue
		Write-Host ($response | ConvertTo-Json -Depth 3) -ForegroundColor Blue
		$accessToken = $response.access_token
		Write-Host ("Access Token for Client ID: " + $accessToken) -ForegroundColor Red
    } catch {
		Write-Host "Failed to get token for Client ID: $clientId" -ForegroundColor White
		Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor White
		#Write-Host "Full Exception: $($_ | ConvertTo-Json -Depth 100)" -ForegroundColor White
		#Write-Output "Full Exception Details:"
		#$_.Exception | Format-List -Property *
		continue  # Ensures the loop moves to the next iteration
    }

}