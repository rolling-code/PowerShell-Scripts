#1) generate a device code.
#$ClientID = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"  # Intune
$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"   # Office
$Scope = ".default offline_access"
$body = @{
"client_id" = $ClientID
"scope" = $Scope  
}
$authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" -Body $body
$authResponse

#Sleep to give time to enter code in Browser
Sleep 60

Write-Host "⚡ request refresh token and access token for the Graph API" -ForegroundColor Green
$GrantType = "urn:ietf:params:oauth:grant-type:device_code"
$body=@{
    "client_id" = $ClientID
    "grant_type" = $GrantType
    "code" = $authResponse.device_code
}
$Tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body -ErrorAction SilentlyContinue
$Tokens
$GraphToken = $Tokens.access_token

Write-Host "⚡ request access token for the ARM API.." -ForegroundColor Green
$scope = 'https://management.azure.com/.default'
$refresh_token = $tokens.refresh_token
$GrantType = 'refresh_token'
$body=@{
    "client_id" = $ClientID
    "scope" = $Scope
    "refresh_token" = $refresh_token
    "grant_type" = $GrantType
}
$Token_output = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body
$token = $Token_output.access_token
$token

