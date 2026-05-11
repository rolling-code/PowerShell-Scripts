# Requires -Version 7.0

<#
.SYNOPSIS
    MSADPT_enumerate_shares2.ps1 - Enumerates network shares on discovered Domain Controllers
    and scans them for findings.

.DESCRIPTION
    This script is part of the MSADPT toolchain.
    It consumes a CSV file of Domain Controllers produced by a previous MSADPT script,
    validates Active Directory connectivity, and prepares per-DC output locations.

    All operational inputs are provided explicitly via command-line parameters.
    The script does not assume the host is domain joined and does not rely on
    config files or session-scoped credentials.

.PARAMETER InputDcCsvPath
    Path to the CSV file containing discovered Domain Controllers.
    Example:
        C:\temp\MSADPT_Output\MSADPT_DCs.csv

.PARAMETER OutputBaseDir
    Base output directory where per-DC output folders will be created.
    Example:
        C:\temp\MSADPT_Output\Shares

.PARAMETER Credential
    Domain credential to use for all Active Directory operations.
    Example:
        -Credential (Get-Credential)

.OUTPUTS
    Script-specific outputs should be documented here once the loop body is reinserted.

.EXAMPLE
    .\MSADPT_enumerate_shares2.ps1 `
        -InputDcCsvPath "C:\temp\MSADPT_Output\MSADPT_DCs.csv" `
        -OutputBaseDir "C:\temp\MSADPT_Output\Shares" `
        -Credential (Get-Credential)
#>

param(
    [Parameter(Mandatory)]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "Input file '$_' does not exist."
        }
        $true
    })]
    [string]$InputDcCsvPath,

    [Parameter(Mandatory)]
    [string]$OutputBaseDir,

    [Parameter(Mandatory)]
    [PSCredential]$Credential
)

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------
# Import helper module from same folder as script
# ---------------------------------------------------------------------
$helpersModulePath = Join-Path $PSScriptRoot 'MSADPT.Helpers.psm1'

if (-not (Test-Path -LiteralPath $helpersModulePath -PathType Leaf)) {
    Write-Error "Required helper module not found at '$helpersModulePath'. Aborting."
    exit 1
}

Import-Module $helpersModulePath -Force -ErrorAction Stop

Write-MSADPTLog -Message "MSADPT_enumerate_shares2.ps1 starting." -Level 'INFO'
Write-MSADPTLog -Message "Input CSV  : $InputDcCsvPath" -Level 'INFO'
Write-MSADPTLog -Message "Output Dir : $OutputBaseDir" -Level 'INFO'

# ---------------------------------------------------------------------
# Ensure output directory exists
# ---------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $OutputBaseDir -PathType Container)) {
    New-Item -Path $OutputBaseDir -ItemType Directory -Force | Out-Null
    Write-MSADPTLog -Message "Created output directory '$OutputBaseDir'." -Level 'INFO'
}


<# 
Write-MSADPTLog -Message "Pre-flight succeeded. DefaultNamingContext: $($rootDSE.defaultNamingContext)" -Level 'INFO'

$ConfigNamingContext = $rootDSE.configurationNamingContext
$DefaultNamingContext = $rootDSE.defaultNamingContext
$SchemaNamingContext  = $rootDSE.schemaNamingContext #>

# ---------------------------------------------------------------------
# Import DC list
# ---------------------------------------------------------------------
$DCs = Import-Csv -Path $InputDcCsvPath
if (-not $DCs) {
    Write-MSADPTLog -Message "No Domain Controllers found in input CSV. Exiting." -Level 'WARNING'
    exit 0
}

Write-MSADPTLog -Message "Imported $(@($DCs).Count) Domain Controller row(s) from '$InputDcCsvPath'." -Level 'INFO'

# ---------------------------------------------------------------------
# Optional module pre-checks for code you may paste into the loop later
# ---------------------------------------------------------------------
$GroupPolicyModuleAvailable = [bool](Get-Module -ListAvailable -Name GroupPolicy)
Write-MSADPTLog -Message "GroupPolicy module available: $GroupPolicyModuleAvailable" -Level 'INFO'

#no wildcard no leading dot
$NetworkShareExcludeExtensions = @(
    'xlsx',
    'zip',
    'jpg',
    'jpeg',
    'png',
    'gif',
    'mp4',
    'avi',
    'mov',
    'iso',
    'dll',
    'exe'
)


$SensitiveFilePatterns = @(
    '*.kdbx',          # KeePass databases
    '*.pfx',           # certificate bundles
    '*.p12',
    '*.pem',
    '*.key',
    '*.ppk',
    '*.ovpn',
    '*.rdp',
    '*.env',
    '*.config',
    '*.ini',
    '*.xml',
    'unattend.xml',
    'groups.xml',
    'web.config',
    'appsettings*.json'
)

$SensitiveKeywords = @(
    'password',
    'passwd',
    'pwd=',
    'secret',
    'token',
    'api key',
    'apikey',
    'client_secret',
    'client secret',
    'private key',
    'BEGIN PRIVATE KEY',
    'BEGIN RSA PRIVATE KEY',
    'BEGIN OPENSSH PRIVATE KEY',
    'connection string',
    'connectionstring',
    'ssh key',
    'certificate password',
    'vpn password',
    'service account',
    'admin password'
)


# ---------------------------------------------------------------------
# Iterate and process each Domain Controller
# ---------------------------------------------------------------------
foreach ($DC in $DCs) {
	$DCName = $DC.Name
    $DCIpAddress = $DC.IPv4Address
    Write-MSADPTLog -Message "--------------------------------------------------------"
    Write-MSADPTLog -Message "Processing Domain Controller for Shares: $DCName ($DCIpAddress)" -Level 'INFO'
    Write-MSADPTLog -Message "--------------------------------------------------------"

    $CurrentDCOutputDir = Join-Path $OutputBaseDir $DCName
    if (-not (Test-Path $CurrentDCOutputDir)) {
        New-Item -Path $CurrentDCOutputDir -ItemType Directory -Force | Out-Null
    }

    $SharesFound = @()
    $SensitiveFilesFound = @()

    # 1. Enumerate Shares on the DC
    if (Prompt-User -PromptText "Proceed to enumerate network shares on ${DCName} ($DCIpAddress) with WSMan/Negotiate?") {
        Write-MSADPTLog -Message "Running 'New-CimSession -ComputerName ${DCName}' to enumerate shares."
        try {
            # Use WMI to list shares on the remote DC
<#             $RemoteShares = Get-WmiObject -Class Win32_Share -ComputerName $DCName -Credential $Credential -ErrorAction Stop | Select-Object Name, Path, Description
            if ($RemoteShares) {
                Write-MSADPTLog -Message "Discovered $($RemoteShares.Count) share(s) on ${DCName}:"
                foreach ($Share in $RemoteShares) {
                    $SharesFound += [PSCustomObject]@{
                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        DCName    = $DCName
                        ShareName = $Share.Name
                        SharePath = $Share.Path
                        Description = $Share.Description
                    }
                    Write-MSADPTLog -Message "  - \\${DCName}\${Share.Name} (${Share.Path})"
                } #>
				
				$RemoteShares = @()
				$cimSession = $null

				try {
					Write-MSADPTLog -Message "Creating CIM session to '$DCName' using WSMan/Negotiate." -Level 'INFO'
					$cimSession = New-CimSession -ComputerName $DCName -Credential $Credential -Authentication Negotiate -ErrorAction Stop

					try {
						if (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue) {
							Write-MSADPTLog -Message "Trying preferred method: Get-SmbShare -CimSession for '$DCName'." -Level 'INFO'

							$RemoteShares = Get-SmbShare -CimSession $cimSession -ErrorAction Stop |
								Select-Object Name, Path, Description
						}
						else {
							throw "Get-SmbShare cmdlet is not available on this system."
						}
					}
					catch {
						Write-MSADPTLog -Message "Preferred method failed for '$DCName': $($_.Exception.Message). Falling back to Get-CimInstance Win32_Share." -Level 'WARNING'

						$RemoteShares = Get-CimInstance -ClassName Win32_Share -CimSession $cimSession -ErrorAction Stop |
							Select-Object Name, Path, Description
					}

					if ($RemoteShares) {
						Write-MSADPTLog -Message "Discovered $($RemoteShares.Count) share(s) on '$DCName'." -Level 'INFO'

						foreach ($Share in $RemoteShares) {
							$SharesFound += [PSCustomObject]@{
								Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
								DCName      = $DCName
								ShareName   = $Share.Name
								SharePath   = $Share.Path
								Description = $Share.Description
							}

							Write-MSADPTLog -Message "  - \\$DCName\$($Share.Name) ($($Share.Path))" -Level 'INFO'
						}
					}
					else {
						Write-MSADPTLog -Message "No shares returned from '$DCName'." -Level 'INFO'
					}
				}
				catch {
					Write-MSADPTLog -Message "Failed to enumerate shares on '$DCName': $($_.Exception.Message)" -Level 'ERROR'
				}
				finally {
					if ($null -ne $cimSession) {
						Remove-CimSession $cimSession -ErrorAction SilentlyContinue
						Write-MSADPTLog -Message "Closed CIM session to '$DCName'." -Level 'INFO'
					}
				}


                <# $SharesCsvPath = Join-Path $CurrentDCOutputDir "MSADPT_Shares_Discovered_${DCName}_$ScriptStartTime.csv"
                $SharesFound | Export-Csv -Path $SharesCsvPath -NoTypeInformation -Force
                Write-MSADPTLog -Message "Discovered shares on ${DCName} saved to $SharesCsvPath." #>
				
				
				if (@($SharesFound).Count -gt 0) {
					$SharesCsvPath = Join-Path $CurrentDCOutputDir "MSADPT_Shares_Discovered_${DCName}_$ScriptStartTime.csv"
					$SharesFound | Export-Csv -Path $SharesCsvPath -NoTypeInformation -Force
					Write-MSADPTLog -Message "Discovered shares on ${DCName} saved to $SharesCsvPath."
				}

                # 2. Iterate through each share and perform sensitive file scanning
                foreach ($Share in $SharesFound) {
                    $FullSharePath = "\\${DCName}\${Share.Name}"
                    if (Prompt-User -PromptText "Proceed to scan share '${FullSharePath}' for sensitive data? This may take time.") {
                        Write-MSADPTLog -Message "Scanning share '${FullSharePath}' for sensitive files and content."
                        try {
                            # Get all files, excluding extensions defined in config, but explicitly include sensitive patterns
                            # -File switch ensures only files, not directories, are returned
                            <# $FilesToScan = Get-ChildItem -Path $FullSharePath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                                $IsExcluded = $NetworkShareExcludeExtensions -contains $_.Extension.TrimStart('.')
                                $IsSensitivePattern = $SensitiveFilePatterns | Where-Object { $_ -like $_.FullName } # Check against full file name with wildcard
                                -not $IsExcluded -or $IsSensitivePattern # Include if not excluded OR if it matches a sensitive pattern
                            } #>
							
							$FilesToScan = Get-ChildItem -Path $FullSharePath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
								$file = $_
								$IsExcluded = @($NetworkShareExcludeExtensions) -contains $file.Extension.TrimStart('.')
								$IsSensitivePattern = @(
									$SensitiveFilePatterns | Where-Object { $file.FullName -like $_ }
								).Count -gt 0
								(-not $IsExcluded) -or $IsSensitivePattern
							}


                            foreach ($File in $FilesToScan) {
                                $FilePath = $File.FullName
                                $DetectedKeywords = @()

                                # Check file content for sensitive keywords
                                if ($SensitiveKeywords.Count -gt 0) {
                                    Write-MSADPTLog -Message "  - Checking file content: ${FilePath}"
                                    foreach ($Keyword in $SensitiveKeywords) {
                                        # Use Select-String for efficient keyword search, case-insensitive
                                        if (Get-Content -Path $FilePath -ErrorAction SilentlyContinue | Select-String -Pattern $Keyword -SimpleMatch -CaseSensitive:$false -Quiet) {
                                            $DetectedKeywords += $Keyword
                                        }
                                    }
                                }

                                if ($DetectedKeywords.Count -gt 0 -or ($SensitiveFilePatterns | Where-Object { $File.FullName -like $_ }).Count -gt 0) {
                                    $Reason = if ($DetectedKeywords.Count -gt 0) {"Keywords: $($DetectedKeywords -join ', ')"} else {"Pattern match"}
                                    $SensitiveFilesFound += [PSCustomObject]@{
                                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                                        DCName    = $DCName
                                        ShareName = $Share.Name
                                        FilePath  = $FilePath
                                        SensitivityReason = $Reason
                                    }
                                    Write-MSADPTLog -Message "    [!!!] Sensitive file found: ${FilePath} (Reason: ${Reason})" -Level 'WARNING'
                                }
                            }
                            Write-MSADPTLog -Message "Finished scanning share '${FullSharePath}'. Found $($FilesToScan.Count) files."
                        } catch {
                            Write-MSADPTLog -Message "Failed to scan share '${FullSharePath}': $($_.Exception.Message)" -Level 'ERROR'
                        }
                    } else {
                        Write-MSADPTLog -Message "Skipping scan for share '${FullSharePath}'."
                    }
                }

                if ($SensitiveFilesFound.Count -gt 0) {
                    $SensitiveFilesCsvPath = Join-Path $CurrentDCOutputDir "MSADPT_Shares_SensitiveFiles_${DCName}_$ScriptStartTime.csv"
                    $SensitiveFilesFound | Export-Csv -Path $SensitiveFilesCsvPath -NoTypeInformation -Force
                    Write-MSADPTLog -Message "Sensitive files found on ${DCName} saved to $SensitiveFilesCsvPath." -Level 'WARNING'
                } else {
                    Write-MSADPTLog -Message "No sensitive files found on any shares for ${DCName}."
                }

            <# } else {
                Write-MSADPTLog -Message "No shares found on ${DCName}." -Level 'INFO'
            } #>
        } catch {
            Write-MSADPTLog -Message "Failed to enumerate shares on ${DCName}: $($_.Exception.Message)" -Level 'ERROR'
        }
    } else {
        Write-MSADPTLog -Message "Skipping network share enumeration for ${DCName}."
    }
}
    
Write-MSADPTLog -Message "MSADPT_enumerate_shares2.ps1 completed." -Level 'INFO'
