# Requires -Version 7.0

<#
.SYNOPSIS
    MSADPT_scan_network2.ps1 - Performs network discovery and service checks.

.DESCRIPTION
    This script is the MSADPT network reconnaissance stage.
    It consumes explicitly supplied target ranges and output paths.

    All operational inputs are provided explicitly via command-line parameters.
    The script does not assume:
    - a config file
    - a domain-joined host
    - session-scoped credentials
    - automatically derived local network ranges

    The helper module is imported from the same folder as the executing script.

.PARAMETER Credential
    Credential used for remote operations that require authentication.
    Example:
        -Credential (Get-Credential)

.PARAMETER NetworkRanges
    One or more explicit IPv4 target ranges to process.
    Supported examples:
        "10.10.10.0/24"
        "10.10.10.10-10.10.10.50"

.PARAMETER CommonPorts
    One or more ports to check.
    Example:
        -CommonPorts 445,3389,5985,5986

.PARAMETER UseNmapIfAvailable
    Indicates whether the script should attempt to use nmap if it is present in PATH.
    Example:
        -UseNmapIfAvailable $true

.PARAMETER CheckSMBSigning
    Indicates whether SMB signing checks should be performed in the main scan logic.
    Example:
        -CheckSMBSigning $true

.PARAMETER OutputBaseDir
    Base directory for any per-run or raw output artifacts.
    Example:
        -OutputBaseDir "C:\temp\MSADPT_Output\Network"

.PARAMETER OutputHostsCsvPath
    Explicit CSV output path for discovered hosts.
    Example:
        -OutputHostsCsvPath "C:\temp\MSADPT_Output\MSADPT_Network_Hosts.csv"

.PARAMETER OutputOpenPortsCsvPath
    Explicit CSV output path for open ports.
    Example:
        -OutputOpenPortsCsvPath "C:\temp\MSADPT_Output\MSADPT_OpenPorts.csv"

.PARAMETER OutputSmbSigningCsvPath
    Explicit CSV output path for SMB signing results.
    Example:
        -OutputSmbSigningCsvPath "C:\temp\MSADPT_Output\MSADPT_SMBSigning_Status.csv"

.OUTPUTS
    - Hosts CSV at -OutputHostsCsvPath
    - Open ports CSV at -OutputOpenPortsCsvPath
    - SMB signing CSV at -OutputSmbSigningCsvPath

.EXAMPLE
    .\MSADPT_scan_network2.ps1 `
        -Credential (Get-Credential) `
        -NetworkRanges "10.10.10.0/24","10.20.30.10-10.20.30.20" `
        -CommonPorts 445,3389,5985 `
        -UseNmapIfAvailable $true `
        -CheckSMBSigning $true `
        -OutputBaseDir "C:\temp\MSADPT_Output\Network" `
        -OutputHostsCsvPath "C:\temp\MSADPT_Output\MSADPT_Network_Hosts.csv" `
        -OutputOpenPortsCsvPath "C:\temp\MSADPT_Output\MSADPT_OpenPorts.csv" `
        -OutputSmbSigningCsvPath "C:\temp\MSADPT_Output\MSADPT_SMBSigning_Status.csv"
#>

param(
    [Parameter(Mandatory)]
	[ValidateNotNull()]
    [PSCredential]$Credential,

    [Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
    [string[]]$NetworkRanges,

    [Parameter(Mandatory)]
    [ValidateRange(1, 65535)]
    [int[]]$CommonPorts,

    [Parameter(Mandatory)]
    [bool]$UseNmapIfAvailable,

    [Parameter(Mandatory)]
    [bool]$CheckSMBSigning,

    [Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
    [string]$OutputBaseDir,

    [Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
    [string]$OutputHostsCsvPath,

    [Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
    [string]$OutputOpenPortsCsvPath,

    [Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
    [string]$OutputSmbSigningCsvPath
)

# ---------------------------------------------------------------------
# Import helper module from same folder as script
# ---------------------------------------------------------------------
$helpersModulePath = Join-Path $PSScriptRoot 'MSADPT.Helpers.psm1'

if (-not (Test-Path -LiteralPath $helpersModulePath -PathType Leaf)) {
    Write-Error "Required helper module not found at '$helpersModulePath'. Aborting."
    exit 1
}

Import-Module $helpersModulePath -Force -ErrorAction Stop

# ---------------------------------------------------------------------
# Core run metadata
# ---------------------------------------------------------------------
$ScriptStartTime = Get-Date -Format "yyyyMMdd_HHmmss"

Write-MSADPTLog -Message "MSADPT_scan_network2.ps1 starting." -Level 'INFO'
Write-MSADPTLog -Message "NetworkRanges           : $($NetworkRanges -join ', ')" -Level 'INFO'
Write-MSADPTLog -Message "CommonPorts             : $($CommonPorts -join ', ')" -Level 'INFO'
Write-MSADPTLog -Message "UseNmapIfAvailable      : $UseNmapIfAvailable" -Level 'INFO'
Write-MSADPTLog -Message "CheckSMBSigning         : $CheckSMBSigning" -Level 'INFO'
Write-MSADPTLog -Message "OutputBaseDir           : $OutputBaseDir" -Level 'INFO'
Write-MSADPTLog -Message "OutputHostsCsvPath      : $OutputHostsCsvPath" -Level 'INFO'
Write-MSADPTLog -Message "OutputOpenPortsCsvPath  : $OutputOpenPortsCsvPath" -Level 'INFO'
Write-MSADPTLog -Message "OutputSmbSigningCsvPath : $OutputSmbSigningCsvPath" -Level 'INFO'

# ---------------------------------------------------------------------
# Ensure output directories exist
# ---------------------------------------------------------------------
$allOutputPaths = @(
    $OutputBaseDir,
    (Split-Path -Path $OutputHostsCsvPath -Parent),
    (Split-Path -Path $OutputOpenPortsCsvPath -Parent),
    (Split-Path -Path $OutputSmbSigningCsvPath -Parent)
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

foreach ($path in $allOutputPaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
        Write-MSADPTLog -Message "Created directory '$path'." -Level 'INFO'
    }
}

# ---------------------------------------------------------------------
# Module and tool checks
# ---------------------------------------------------------------------
<# Write-MSADPTLog -Message "Performing module and tool availability checks." -Level 'INFO'

$RequiredModules = @('NetAdapter', 'NetTCPIP')
foreach ($module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-MSADPTLog -Message "Required PowerShell module '$module' is not available. Aborting." -Level 'ERROR'
        exit 1
    }

    if (-not (Get-Module -Name $module)) {
        Import-Module $module -ErrorAction Stop
        Write-MSADPTLog -Message "Imported PowerShell module '$module'." -Level 'INFO'
    }
} #>

# ---------------------------------------------------------------------
# Nmap availability evaluation
# ---------------------------------------------------------------------
$UseNmap = $false
if ($UseNmapIfAvailable) {
    if (Get-Command -Name 'nmap' -ErrorAction SilentlyContinue) {
        $UseNmap = $true
        Write-MSADPTLog -Message "nmap detected in PATH. UseNmap = True." -Level 'INFO'
    }
    else {
        Write-MSADPTLog -Message "UseNmapIfAvailable was True, but nmap was not found in PATH. UseNmap = False." -Level 'WARNING'
    }
}
else {
    Write-MSADPTLog -Message "UseNmapIfAvailable was False. UseNmap = False." -Level 'INFO'
}

# ---------------------------------------------------------------------
# Transitional variables preserved for compatibility with pasted core
# ---------------------------------------------------------------------
$LiveHosts = @()
$OpenPorts = @()
$SMBSigningStatus = @()

# --- Function to get IP range from CIDR or simple range string ---
function Expand-IpRange {
    param(
        [Parameter(Mandatory)]
        [string]$Range
    )

    $IPs = @()

    if ($Range -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        $baseIp = [System.Net.IPAddress]::Parse($Matches[1])
        $prefixLength = [int]$Matches[2]

        if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
            Write-MSADPTLog -Message "Invalid CIDR prefix length in '$Range'. Skipping." -Level 'WARNING'
            return @()
        }

        $baseBytes = $baseIp.GetAddressBytes()
        [Array]::Reverse($baseBytes)
        $baseInt = [BitConverter]::ToUInt32($baseBytes, 0)

        $maskInt = if ($prefixLength -eq 0) {
            [uint32]0
        } else {
            [uint32]::MaxValue -shl (32 - $prefixLength)
        }

        $networkInt = $baseInt -band $maskInt
        $broadcastInt = $networkInt -bor (-bnot $maskInt)

        switch ($prefixLength) {
            32 {
                $IPs += $baseIp.ToString()
            }
            31 {				
				for ([uint64]$addr = [uint64]$networkInt; $addr -le [uint64]$broadcastInt; $addr++) {
						$bytes = [BitConverter]::GetBytes([uint32]$addr)
						[Array]::Reverse($bytes)
						$IPs += [System.Net.IPAddress]::new($bytes).ToString()
					}

            }
            default {
                $firstHost = $networkInt + 1
                $lastHost = $broadcastInt - 1
				
				for ([uint64]$addr = [uint64]$firstHost; $addr -le [uint64]$lastHost; $addr++) {
					$bytes = [BitConverter]::GetBytes([uint32]$addr)
					[Array]::Reverse($bytes)
					$IPs += [System.Net.IPAddress]::new($bytes).ToString()
				}
            }
        }
    }
    elseif ($Range -match '^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$') {
        $startIp = [System.Net.IPAddress]::Parse($Matches[1])
        $endIp = [System.Net.IPAddress]::Parse($Matches[2])

        $startBytes = $startIp.GetAddressBytes()
        [Array]::Reverse($startBytes)
        $startInt = [BitConverter]::ToUInt32($startBytes, 0)

        $endBytes = $endIp.GetAddressBytes()
        [Array]::Reverse($endBytes)
        $endInt = [BitConverter]::ToUInt32($endBytes, 0)

        if ($startInt -gt $endInt) {
            Write-MSADPTLog -Message "Invalid IP range '$Range' (start greater than end). Skipping." -Level 'WARNING'
            return @()
        }

        foreach ($addr in $startInt..$endInt) {
            $bytes = [BitConverter]::GetBytes([uint32]$addr)
            [Array]::Reverse($bytes)
            $IPs += [System.Net.IPAddress]::new($bytes).ToString()
        }
    }
    else {
        Write-MSADPTLog -Message "Invalid IP range format for '$Range'. Skipping." -Level 'WARNING'
    }

    return $IPs | Select-Object -Unique
}


function Invoke-MSADPTNmapSmbSigning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [string]$OutputDir,

        [Parameter(Mandatory)]
        [string]$ScriptStartTime
    )

    $nmapCmd = Get-Command nmap.exe -ErrorAction SilentlyContinue
    if (-not $nmapCmd) {
        $nmapCmd = Get-Command nmap -ErrorAction SilentlyContinue
    }

    if (-not $nmapCmd) {
        return [PSCustomObject]@{
            Success     = $false
            Status      = $null
            Note        = "nmap not found in PATH."
            RawFilePath = $null
            ScriptUsed  = $null
        }
    }

    $safeTarget = $Target -replace '[^\w\.-]', '_'

    $scriptOrder = @(
        'smb2-security-mode',
        'smb-security-mode'
    )

    foreach ($scriptName in $scriptOrder) {
        $rawPath = Join-Path $OutputDir ("MSADPT_{0}_{1}_{2}.txt" -f $scriptName, $safeTarget, $ScriptStartTime)

        $args = @(
            '-Pn',
            '-n',
            '-p', '445',
            '--script', $scriptName,
            '-oN', $rawPath,
            $Target
        )

        Write-MSADPTLog -Message "      - Nmap fallback: running '$($nmapCmd.Source) $($args -join ' ')'."

        $null = & $nmapCmd.Source @args 2>&1
        $exitCode = $LASTEXITCODE

        Write-MSADPTLog -Message "      - Nmap fallback: $scriptName exited with code $exitCode. Raw output file: $rawPath"

        if (-not (Test-Path $rawPath)) {
            Write-MSADPTLog -Message "      - Nmap fallback: expected raw output file was not created for $scriptName." -Level 'WARNING'
            continue
        }

        $raw = Get-Content $rawPath -Raw -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($raw)) {
            Write-MSADPTLog -Message "      - Nmap fallback: raw output file is empty for $scriptName." -Level 'WARNING'
            continue
        }

        # smb2-security-mode output
        if ($raw -match 'Message signing enabled and required') {
            return [PSCustomObject]@{
                Success     = $true
                Status      = 'Required (Enabled)'
                Note        = "Nmap $scriptName | Message signing enabled and required | RawFile=$rawPath"
                RawFilePath = $rawPath
                ScriptUsed  = $scriptName
            }
        }
        elseif ($raw -match 'Message signing enabled but not required') {
            return [PSCustomObject]@{
                Success     = $true
                Status      = 'Enabled (Not Required)'
                Note        = "Nmap $scriptName | Message signing enabled but not required | RawFile=$rawPath"
                RawFilePath = $rawPath
                ScriptUsed  = $scriptName
            }
        }
        elseif ($raw -match 'Message signing is disabled and not required!') {
            return [PSCustomObject]@{
                Success     = $true
                Status      = 'Disabled'
                Note        = "Nmap $scriptName | Message signing is disabled and not required | RawFile=$rawPath"
                RawFilePath = $rawPath
                ScriptUsed  = $scriptName
            }
        }
        elseif ($raw -match 'Message signing is disabled!') {
            return [PSCustomObject]@{
                Success     = $true
                Status      = 'Disabled'
                Note        = "Nmap $scriptName | Message signing is disabled | RawFile=$rawPath"
                RawFilePath = $rawPath
                ScriptUsed  = $scriptName
            }
        }

        # smb-security-mode output
        if ($raw -match 'message_signing:\s*required') {
            return [PSCustomObject]@{
                Success     = $true
                Status      = 'Required (Enabled)'
                Note        = "Nmap $scriptName | message_signing: required | RawFile=$rawPath"
                RawFilePath = $rawPath
                ScriptUsed  = $scriptName
            }
        }
        elseif ($raw -match 'message_signing:\s*disabled') {
            return [PSCustomObject]@{
                Success     = $true
                Status      = 'Disabled'
                Note        = "Nmap $scriptName | message_signing: disabled | RawFile=$rawPath"
                RawFilePath = $rawPath
                ScriptUsed  = $scriptName
            }
        }
        elseif ($raw -match 'message_signing:\s*supported') {
            return [PSCustomObject]@{
                Success     = $true
                Status      = 'Enabled (Not Required)'
                Note        = "Nmap $scriptName | message_signing: supported | RawFile=$rawPath"
                RawFilePath = $rawPath
                ScriptUsed  = $scriptName
            }
        }
        else {
            Write-MSADPTLog -Message "      - Nmap fallback: no signing string parsed from $scriptName output." -Level 'WARNING'
        }
    }

    return [PSCustomObject]@{
        Success     = $false
        Status      = $null
        Note        = "nmap ran, but no SMB signing result could be parsed."
        RawFilePath = $null
        ScriptUsed  = $null
    }
}


# ---------------------------------------------------------------------
# Main scan loop
# Paste your original foreach ($Range in $NetworkRanges) { } body here
# after applying the variable/path changes listed below.
# ---------------------------------------------------------------------
foreach ($Range in $NetworkRanges) {
	$CurrentRangeLiveHosts = @()
	$CurrentRangeOpenPorts = @()
	$CurrentRangeSMBSigningStatus = @()

    Write-MSADPTLog -Message "Expanding IP range: $Range"
    $TargetIPs = Expand-IpRange -Range $Range
    Write-MSADPTLog -Message "Initiating host discovery for range: $Range (found $($TargetIPs.Count) IPs to check)."

    if (Prompt-User -PromptText "Proceed with host discovery (ping sweep) for ${Range}? This may be noisy.") {
        Write-MSADPTLog -Message "Running host discovery for $Range."

        foreach ($IP in $TargetIPs) {
            # TODO:
            # Paste your existing host discovery logic here.
            # This block should append discovered hosts to $LiveHosts as [PSCustomObject] rows.
			# Test-Connection with -Quiet and -BufferSize 32 to simulate a single small packet
			# Increased timeout to 2 seconds for reliability over various network conditions
			if (Test-Connection -ComputerName $IP -Count 1 -BufferSize 32 -Quiet -TimeoutSeconds 2 -ErrorAction SilentlyContinue) {
				Write-MSADPTLog -Message "  - Host $IP is online."
				$hostRow = [PSCustomObject]@{
					Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
					IPAddress = $IP
					Status    = "Online"
				}

				$CurrentRangeLiveHosts += $hostRow
				$LiveHosts += $hostRow
			}
        }
    }
    else {
        Write-MSADPTLog -Message "Skipping host discovery for $Range."
    }

    if (@($CurrentRangeLiveHosts).Count -gt 0) {

        $LiveHosts | Export-Csv -Path $OutputHostsCsvPath -NoTypeInformation -Force
        Write-MSADPTLog -Message "Discovered $($LiveHosts.Count) live hosts. Details saved to $OutputHostsCsvPath."

        # --- Port Scan on Live Hosts ---
        if (Prompt-User -PromptText "Proceed with port scanning on discovered live hosts ($($CurrentRangeLiveHosts.Count) hosts)? This can be noisy.") {
            Write-MSADPTLog -Message "Initiating port scan on live hosts."

            foreach ($LiveHost in $CurrentRangeLiveHosts) {
                $IP = $LiveHost.IPAddress
                Write-MSADPTLog -Message "  - Scanning ports on host: $IP"

                if ($UseNmap -and (Prompt-User -PromptText "Use Nmap for aggressive port scanning on $IP (ports: $($CommonPorts -join ','))?")) {
                    Write-MSADPTLog -Message "Running nmap path for $IP."

                    try {
                        # TODO:
                        # Paste your existing nmap-based port scan logic here.
                        # This block should append open ports to $OpenPorts as [PSCustomObject] rows.
						# Nmap execution: -p specifies ports, -T4 for faster scan, -Pn to skip host discovery (already done)
                        # -oX output to XML, then convert for parsing
                        $NmapRawOutput = (nmap -p $($CommonPorts -join ',') -T4 -Pn -oX - $IP | Out-String)
                        [xml]$NmapXml = $NmapRawOutput
						Write-MSADPTLog -Message "Nmap raw output length for ${IP}: $($NmapRawOutput.Length)"

                        if ($NmapXml.nmaprun.host.ports) {
                            $NmapXml.nmaprun.host.ports.port | ForEach-Object {
                                if ($_.state.state -eq 'open') {
                                    $openPortRow = [PSCustomObject]@{
										Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
										IPAddress = $IP
										Port      = $_.portid
										Protocol  = $_.protocol
										Service   = $_.service.name
										State     = 'Open'
										Method    = 'Nmap'
									}

									$CurrentRangeOpenPorts += $openPortRow
									$OpenPorts += $openPortRow
                                    Write-MSADPTLog -Message "    [OPEN] Port $($_.portid)/$($_.protocol) ($($_.service.name)) on $IP"
                                }
                            }
                        }
                    }
                    catch {
                        Write-MSADPTLog -Message "nmap scan failed for ${IP}: $($_.Exception.Message). Falling back to the alternate port-check method." -Level 'ERROR'
                        Write-MSADPTLog -Message "nmap exception type for ${IP}: $($_.Exception.GetType().FullName)" -Level 'ERROR'
                        Write-MSADPTLog -Message "nmap exception details for ${IP}: $($_ | Out-String)" -Level 'ERROR'

                        foreach ($Port in $CommonPorts) {

                            if ($Port -lt 1 -or $Port -gt 65535) {
                                Write-MSADPTLog -Message "    - Skipping invalid port value '$Port' on $IP." -Level 'WARNING'
                                continue
                            }

                            Write-MSADPTLog -Message "    - Checking port $Port on $IP using the alternate port-check method."

                            # TODO:
                            # Paste your existing non-nmap port check logic here.
                            # This block should append open ports to $OpenPorts as [PSCustomObject] rows.
							if (Test-NetConnection -ComputerName $IP -Port $Port -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {
                                $openPortRow = [PSCustomObject]@{
									Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
									IPAddress = $IP
									Port      = $Port
									Protocol  = 'TCP'
									Service   = 'Unknown'
									State     = 'Open'
									Method    = 'Test-NetConnection'
								}

								$CurrentRangeOpenPorts += $openPortRow
								$OpenPorts += $openPortRow
                                Write-MSADPTLog -Message "    [OPEN] Port $Port on $IP"
                            }
                        }
                    }
                }
                else {
                    Write-MSADPTLog -Message "Running the non-nmap port check path on $IP (ports: $($CommonPorts -join ','))."

                    foreach ($Port in $CommonPorts) {
                        Write-MSADPTLog -Message "    - Checking port $Port on $IP."

                        # TODO:
                        # Paste your existing non-nmap port check logic here.
                        # This block should append open ports to $OpenPorts as [PSCustomObject] rows.
						if (Test-NetConnection -ComputerName $IP -Port $Port -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {
                            $openPortRow = [PSCustomObject]@{
								Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
								IPAddress = $IP
								Port      = $Port
								Protocol  = 'TCP'
								Service   = 'Unknown'
								State     = 'Open'
								Method    = 'Test-NetConnection'
							}

							$CurrentRangeOpenPorts += $openPortRow
							$OpenPorts += $openPortRow
                            Write-MSADPTLog -Message "    [OPEN] Port $Port on $IP"
                        }
                    }
                }
            }
        }
        else {
            Write-MSADPTLog -Message "Skipping port scanning."
        }

        if (@($CurrentRangeOpenPorts).Count -gt 0) {
            $OpenPorts | Export-Csv -Path $OutputOpenPortsCsvPath -NoTypeInformation -Force
            Write-MSADPTLog -Message "Found $($OpenPorts.Count) open ports. Details saved to $OutputOpenPortsCsvPath."

            # --- Check SMB Signing Status ---
            if ($CheckSMBSigning) {
                $SMBEnabledHosts = $CurrentRangeOpenPorts |
				Where-Object { ($_.Port -eq 445 -or $_.Port -eq 139) -and $_.State -eq 'Open' } |
				Select-Object -ExpandProperty IPAddress -Unique

                if (@($SMBEnabledHosts).Count -gt 0) {
                    if (Prompt-User -PromptText "Proceed to check SMB signing status on $($SMBEnabledHosts.Count) host(s)?") {
                        Write-MSADPTLog -Message "Checking SMB signing status on hosts with open SMB ports."

                        foreach ($SMBHostIP in $SMBEnabledHosts) {
                            Write-MSADPTLog -Message "  - Checking SMB signing for $SMBHostIP."

                            try {
                                # TODO:
                                # Paste your existing SMB signing status logic here.
                                # This block should append rows to $SMBSigningStatus as [PSCustomObject] rows.
								
								# =========================================================================
								# SMB Signing Check - Multi-Method Native + Nmap Fallbacks
								#
								# Methods attempted in order:
								#   1) Remote Registry (.NET) -> LanmanServer, then LanmanWorkstation
								#   2) WinRM / Invoke-Command -> Get-SmbServerConfiguration
								#   3) WinRS -> remote PowerShell / registry query
								#   4) Nmap -> smb2-security-mode, then smb-security-mode
								#   5) SMB session establishment -> net use + Get-SmbConnection (best-effort)
								#   6) Final fallback -> SMB Reachable (Signing Undetermined)
								#
								# Output shape preserved:
								#   Timestamp, IPAddress, Status, Note
								# =========================================================================

								$Status       = "Unknown"
								$Note         = "Not checked"
								$SMBConfig    = $null
								$ConfigSource = $null
								$RemoteTarget = $SMBHostIP

								Write-MSADPTLog -Message "    - Starting SMB signing analysis for $RemoteTarget."

								# -------------------------------------------------------------------------
								# METHOD 1: Remote Registry via .NET
								# -------------------------------------------------------------------------
								Write-MSADPTLog -Message "    - Method 1/5: Remote Registry via .NET (LanmanServer -> LanmanWorkstation)."

								try {
									$regCandidates = @(
										@{
											Scope = 'LanmanServer'
											Path  = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
										},
										@{
											Scope = 'LanmanWorkstation'
											Path  = 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
										}
									)

									foreach ($candidate in $regCandidates) {
										$enable = Get-MSADPTRemoteRegistryValue `
											-ComputerName $RemoteTarget `
											-SubKey $candidate.Path `
											-ValueName 'EnableSecuritySignature'

										$require = Get-MSADPTRemoteRegistryValue `
											-ComputerName $RemoteTarget `
											-SubKey $candidate.Path `
											-ValueName 'RequireSecuritySignature'

										if ($null -ne $enable -or $null -ne $require) {
											$SMBConfig = [PSCustomObject]@{
												Scope                    = $candidate.Scope
												EnableSecuritySignature  = if ($null -ne $enable) { [int]$enable } else { $null }
												RequireSecuritySignature = if ($null -ne $require) { [int]$require } else { $null }
											}

											$ConfigSource = "Remote Registry ($($candidate.Scope))"
											break
										}
									}
								<# 	$baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
										[Microsoft.Win32.RegistryHive]::LocalMachine,
										$RemoteTarget
									)

									if (-not $baseKey) {
										throw "OpenRemoteBaseKey returned null."
									}

									$regCandidates = @(
										@{
											Scope = 'LanmanServer'
											Path  = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
										},
										@{
											Scope = 'LanmanWorkstation'
											Path  = 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
										}
									)

									foreach ($candidate in $regCandidates) {
										Write-MSADPTLog -Message "      - Remote Registry: trying $($candidate.Scope) at '$($candidate.Path)'."

										try {
											$key = $baseKey.OpenSubKey($candidate.Path)
											if (-not $key) {
												Write-MSADPTLog -Message "      - Remote Registry: key not found or inaccessible for $($candidate.Scope)." -Level 'WARNING'
												continue
											}

											$enable  = $key.GetValue('EnableSecuritySignature', $null)
											$require = $key.GetValue('RequireSecuritySignature', $null)

											Write-MSADPTLog -Message "      - Remote Registry raw values for $($candidate.Scope): EnableSecuritySignature=$enable; RequireSecuritySignature=$require"

											if ($null -ne $enable -or $null -ne $require) {
												$SMBConfig = [PSCustomObject]@{
													Scope                    = $candidate.Scope
													EnableSecuritySignature  = if ($null -ne $enable) { [int]$enable } else { $null }
													RequireSecuritySignature = if ($null -ne $require) { [int]$require } else { $null }
												}
												$ConfigSource = "Remote Registry ($($candidate.Scope))"
												Write-MSADPTLog -Message "      - Remote Registry succeeded using $($candidate.Scope)."
												break
											}
											else {
												Write-MSADPTLog -Message "      - Remote Registry: values missing for $($candidate.Scope)." -Level 'WARNING'
											}
										}
										catch {
											Write-MSADPTLog -Message "      - Remote Registry failed for $($candidate.Scope): $($_.Exception.Message)" -Level 'WARNING'
										}
									} #>
								}
								catch {
									Write-MSADPTLog -Message "      - Remote Registry initialization failed on ${RemoteTarget}: $($_.Exception.Message)" -Level 'WARNING'
								}

								# -------------------------------------------------------------------------
								# METHOD 2: WinRM / Invoke-Command
								# -------------------------------------------------------------------------
								if (-not $SMBConfig) {
									Write-MSADPTLog -Message "    - Method 2/5: WinRM / Invoke-Command -> Get-SmbServerConfiguration."

									try {
										$SMBConfig = Invoke-Command `
											-ComputerName $RemoteTarget `
											-Credential $Credential `
											-Authentication Negotiate `
											-ErrorAction Stop `
											-ScriptBlock {
												try {
													$smb = Get-SmbServerConfiguration -ErrorAction Stop

													return [PSCustomObject]@{
														Scope                    = 'Get-SmbServerConfiguration'
														EnableSecuritySignature  = [int]$smb.EnableSecuritySignature
														RequireSecuritySignature = [int]$smb.RequireSecuritySignature
													}
												}
												catch {
													$paths = @(
														@{
															Scope = 'LanmanServer'
															Path  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
														},
														@{
															Scope = 'LanmanWorkstation'
															Path  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
														}
													)

													foreach ($entry in $paths) {
														try {
															$p = Get-ItemProperty -Path $entry.Path -ErrorAction Stop

															$enable  = $null
															$require = $null

															if ($p.PSObject.Properties.Name -contains 'EnableSecuritySignature') {
																$enable = [int]$p.EnableSecuritySignature
															}
															if ($p.PSObject.Properties.Name -contains 'RequireSecuritySignature') {
																$require = [int]$p.RequireSecuritySignature
															}

															if ($null -ne $enable -or $null -ne $require) {
																return [PSCustomObject]@{
																	Scope                    = $entry.Scope
																	EnableSecuritySignature  = $enable
																	RequireSecuritySignature = $require
																}
															}
														}
														catch {
															# continue
														}
													}

													throw "Could not retrieve SMB signing values via Get-SmbServerConfiguration or remote registry."
												}
											}

										if ($SMBConfig) {
											$ConfigSource = "WinRM/Invoke-Command ($($SMBConfig.Scope))"
											Write-MSADPTLog -Message "      - WinRM succeeded using $($SMBConfig.Scope)."
											Write-MSADPTLog -Message "      - WinRM raw values: EnableSecuritySignature=$($SMBConfig.EnableSecuritySignature); RequireSecuritySignature=$($SMBConfig.RequireSecuritySignature)"
										}
									}
									catch {
										Write-MSADPTLog -Message "      - WinRM / Invoke-Command failed on ${RemoteTarget}: $($_.Exception.Message)" -Level 'WARNING'
									}
								}

								# -------------------------------------------------------------------------
								# METHOD 3: WinRS with hard timeout
								# -------------------------------------------------------------------------
								if (-not $SMBConfig) {
									Write-MSADPTLog -Message "    - Method 3/5: WinRS fallback with hard timeout."

									# Adjust as desired
									$WinRSTimeoutSec = 20

									try {
										# Build the remote PowerShell payload safely without here-string terminator issues
										$winrsPayload = @(
											'try {'
											'    $s = Get-SmbServerConfiguration -ErrorAction Stop'
											'    [Console]::WriteLine(("EnableSecuritySignature={0};RequireSecuritySignature={1}" -f $s.EnableSecuritySignature, $s.RequireSecuritySignature))'
											'}'
											'catch {'
											'    $p = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction Stop'
											'    [Console]::WriteLine(("EnableSecuritySignature={0};RequireSecuritySignature={1}" -f $p.EnableSecuritySignature, $p.RequireSecuritySignature))'
											'}'
										) -join "`r`n"

										$encodedPayload = [Convert]::ToBase64String(
											[System.Text.Encoding]::Unicode.GetBytes($winrsPayload)
										)

										# Convert SecureString password for non-interactive WinRS execution.
										# Note: This places the password on the winrs command line for this process.
										# That is less ideal than an interactive prompt, but it avoids indefinite hangs.
										$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

										try {
											$plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

											$psi = New-Object System.Diagnostics.ProcessStartInfo
											$psi.FileName = 'winrs'

											$psi.Arguments = @(
												"/remote:$RemoteTarget"
												"/username:$($Credential.UserName)"
												"/password:$plainPassword"
												"/noprofile"
												"powershell -NoProfile -EncodedCommand $encodedPayload"
											) -join ' '

											$psi.UseShellExecute        = $false
											$psi.RedirectStandardOutput = $true
											$psi.RedirectStandardError  = $true
											$psi.CreateNoWindow         = $true

											Write-MSADPTLog -Message "      - Launching WinRS for $RemoteTarget with a hard timeout of $WinRSTimeoutSec second(s)."

											$proc = New-Object System.Diagnostics.Process
											$proc.StartInfo = $psi

											$started = $proc.Start()
											if (-not $started) {
												throw "Failed to start winrs process."
											}

											# Wait for exit with a hard timeout
											if (-not $proc.WaitForExit($WinRSTimeoutSec * 1000)) {
												Write-MSADPTLog -Message "      - WinRS timed out after $WinRSTimeoutSec second(s) on $RemoteTarget. Killing process." -Level 'WARNING'
												try {
													$proc.Kill()
												}
												catch {
													Write-MSADPTLog -Message "      - Failed to kill timed-out WinRS process cleanly: $($_.Exception.Message)" -Level 'WARNING'
												}

												throw "WinRS timed out after $WinRSTimeoutSec second(s)."
											}

											# Safe to read now because process already exited and output is tiny
											$stdout = $proc.StandardOutput.ReadToEnd()
											$stderr = $proc.StandardError.ReadToEnd()
											$exitCode = $proc.ExitCode

											$raw = (($stdout, $stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "`n"
											$joined = $raw.Trim()

											Write-MSADPTLog -Message "      - WinRS exited with code $exitCode."
											if (-not [string]::IsNullOrWhiteSpace($joined)) {
												Write-MSADPTLog -Message "      - WinRS output: $joined"
											}

											if ($exitCode -eq 0 -and $joined -match 'EnableSecuritySignature=(\d+);RequireSecuritySignature=(\d+)') {
												$SMBConfig = [PSCustomObject]@{
													Scope                    = 'WinRS'
													EnableSecuritySignature  = [int]$Matches[1]
													RequireSecuritySignature = [int]$Matches[2]
												}

												$ConfigSource = 'WinRS'
												Write-MSADPTLog -Message "      - WinRS succeeded and returned parseable SMB signing values."
											}
											else {
												Write-MSADPTLog -Message "      - WinRS completed, but no parseable SMB signing values were returned." -Level 'WARNING'
											}
										}
										finally {
											if ($bstr -ne [IntPtr]::Zero) {
												[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
											}
											Remove-Variable plainPassword -ErrorAction SilentlyContinue
										}
									}
									catch {
										Write-MSADPTLog -Message "      - WinRS fallback failed on ${RemoteTarget}: $($_.Exception.Message)" -Level 'WARNING'
									}
								}

								# -------------------------------------------------------------------------
								# METHOD 4: Nmap
								# -------------------------------------------------------------------------
								if (-not $SMBConfig) {
									Write-MSADPTLog -Message "    - Method 4/5: Nmap fallback (smb2-security-mode -> smb-security-mode)."

									try {
										$nmapResult = Invoke-MSADPTNmapSmbSigning `
											-Target $RemoteTarget `
											-OutputDir $OutputBaseDir `
											-ScriptStartTime $ScriptStartTime

										if ($nmapResult.Success) {
											$Status = $nmapResult.Status
											$Note   = $nmapResult.Note
											Write-MSADPTLog -Message "      - Nmap succeeded using $($nmapResult.ScriptUsed)."
											Write-MSADPTLog -Message "      - Nmap interpreted SMB signing status for $RemoteTarget as: $Status"
										}
										else {
											Write-MSADPTLog -Message "      - Nmap fallback failed or returned no parseable result: $($nmapResult.Note)" -Level 'WARNING'
										}
									}
									catch {
										Write-MSADPTLog -Message "      - Nmap fallback threw an exception on ${RemoteTarget}: $($_.Exception.Message)" -Level 'WARNING'
									}
								}

								# -------------------------------------------------------------------------
								# METHOD 5: SMB session + Get-SmbConnection
								# -------------------------------------------------------------------------
								if (-not $SMBConfig -and $Status -eq 'Unknown') {
									Write-MSADPTLog -Message "    - Method 5/5: Best-effort SMB session establishment + Get-SmbConnection."

									$sessionEstablished = $false
									$sessionDetails     = $null

									try {
										& net.exe use "\\$RemoteTarget\IPC$" /delete /y *> $null

										$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
										try {
											$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

											Write-MSADPTLog -Message "      - Attempting SMB session to \\$RemoteTarget\IPC$ using net use."
											$null = & net.exe use "\\$RemoteTarget\IPC$" $plain "/user:$($Credential.UserName)" "/persistent:no" 2>&1

											if ($LASTEXITCODE -eq 0) {
												$sessionEstablished = $true
												Write-MSADPTLog -Message "      - SMB session established to \\$RemoteTarget\IPC$."

												try {
													$conn = Get-SmbConnection -ServerName $RemoteTarget -ErrorAction Stop | Select-Object -First 1

													if ($conn) {
														$sessionDetails = @(
															"Dialect=$($conn.Dialect)"
															"Encrypted=$($conn.Encrypted)"
															"ShareName=$($conn.ShareName)"
															"Credential=$($conn.Credential)"
														) -join '; '

														if ($conn.PSObject.Properties.Name -contains 'Signed') {
															$sessionDetails += "; Signed=$($conn.Signed)"
														}

														Write-MSADPTLog -Message "      - Get-SmbConnection succeeded: $sessionDetails"
													}
													else {
														Write-MSADPTLog -Message "      - Get-SmbConnection returned no rows for $RemoteTarget." -Level 'WARNING'
													}
												}
												catch {
													Write-MSADPTLog -Message "      - Get-SmbConnection failed after SMB session establishment: $($_.Exception.Message)" -Level 'WARNING'
												}
											}
											else {
												Write-MSADPTLog -Message "      - net use failed for \\$RemoteTarget\IPC$ (ExitCode=$LASTEXITCODE)." -Level 'WARNING'
											}
										}
										finally {
											if ($bstr -ne [IntPtr]::Zero) {
												[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
											}

											& net.exe use "\\$RemoteTarget\IPC$" /delete /y *> $null
										}
									}
									catch {
										Write-MSADPTLog -Message "      - SMB session fallback failed on ${RemoteTarget}: $($_.Exception.Message)" -Level 'WARNING'
									}

									if ($sessionEstablished -and $sessionDetails) {
										$Status = "SMB Reachable (Signing Undetermined)"
										$Note   = "SMB session established; management and nmap checks failed; $sessionDetails"
									}
									elseif ($sessionEstablished) {
										$Status = "SMB Reachable (Signing Undetermined)"
										$Note   = "SMB session established; management and nmap checks failed"
									}
									else {
										$Status = "SMB Reachable (Signing Undetermined)"
										$Note   = "SMB port reachable; remote registry, WinRM, WinRS, nmap, and SMB session detail checks failed or were denied"
									}
								}

								# -------------------------------------------------------------------------
								# Interpret native config values if retrieved
								# -------------------------------------------------------------------------
								if ($SMBConfig) {
									$EnableSecuritySignature  = $SMBConfig.EnableSecuritySignature
									$RequireSecuritySignature = $SMBConfig.RequireSecuritySignature

									Write-MSADPTLog -Message "    - Interpreting values from $ConfigSource."
									Write-MSADPTLog -Message "      - EnableSecuritySignature=$EnableSecuritySignature"
									Write-MSADPTLog -Message "      - RequireSecuritySignature=$RequireSecuritySignature"

									if ($RequireSecuritySignature -eq 1) {
										$Status = "Required (Enabled)"
									}
									elseif ($EnableSecuritySignature -eq 1) {
										$Status = "Enabled (Not Required)"
									}
									elseif ($EnableSecuritySignature -eq 0 -and $RequireSecuritySignature -eq 0) {
										$Status = "Disabled"
									}
									else {
										$Status = "Unknown"
									}

									$Note = "$ConfigSource | EnableSecuritySignature=$EnableSecuritySignature; RequireSecuritySignature=$RequireSecuritySignature"
								}

								if ($Status -ne 'Unknown') {
									$smbRow = [PSCustomObject]@{
										Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
										IPAddress = $SMBHostIP
										Status    = $Status
										Note      = $Note
									}

									$CurrentRangeSMBSigningStatus += $smbRow
									$SMBSigningStatus += $smbRow

									Write-MSADPTLog -Message "    - Final SMB Signing Status for ${SMBHostIP}: $Status"
									Write-MSADPTLog -Message "    - Final SMB Signing Note   for ${SMBHostIP}: $Note"
								}
								else {
									Write-MSADPTLog -Message "    - No SMB signing result was produced for ${SMBHostIP}; nothing will be written for this host." -Level 'WARNING'
								}
                            }
                            catch {
                                Write-MSADPTLog -Message "    - Failed to check SMB signing for ${SMBHostIP}: $($_.Exception.Message)" -Level 'ERROR'
                            }
                        }
                    }
                    else {
                        Write-MSADPTLog -Message "Skipping SMB signing status check."
                    }
                }
                else {
                    Write-MSADPTLog -Message "No hosts with open SMB ports found to check SMB signing. dID YOU SPECIFY 445 OR 139?" -Level 'INFO'
                }
            }
            else {
				Write-MSADPTLog -Message "SMB signing check is disabled by parameter." -Level 'INFO'
			}
		}
	}
}

if (@($SMBSigningStatus).Count -gt 0) {
    $SMBSigningStatus | Export-Csv -Path $OutputSmbSigningCsvPath -NoTypeInformation -Force
    Write-MSADPTLog -Message "SMB signing results written to $OutputSmbSigningCsvPath." -Level 'INFO'
}
else {
    Write-MSADPTLog -Message "No SMB signing results were collected." -Level 'WARNING'
}

Write-MSADPTLog -Message "MSADPT_scan_network2.ps1 completed." -Level 'INFO'
