function Write-MSADPTLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO','WARNING','ERROR','PROMPT','TREASUREFOUND','PASS','FAIL','REVIEW')]
        [string]$Level = 'INFO',

        [Parameter()]
        [string]$LogFilePath
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp][$Level] $Message"

    $foregroundColor = switch ($Level) {
        'INFO'          { 'Gray' }
        'WARNING'       { 'Yellow' }
        'ERROR'         { 'Red' }
        'PROMPT'        { 'Cyan' }
        'TREASUREFOUND' { 'Green' }
        'PASS'          { 'Green' }
        'FAIL'          { 'Red' }
        'REVIEW'        { 'Magenta' }
        default         { 'White' }
    }

    Write-Host $entry -ForegroundColor $foregroundColor

    if (-not [string]::IsNullOrWhiteSpace($LogFilePath)) {
        try {
            Add-Content -Path $LogFilePath -Value $entry -ErrorAction Stop
        }
        catch {
            Write-Host "[$timestamp][WARNING] Failed to write to log file '$LogFilePath': $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}


function Prompt-User {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PromptText
    )

    Write-MSADPTLog -Message "$PromptText [Y/N]:" -Level 'PROMPT'
    $response = Read-Host

    return ($response -eq 'Y' -or $response -eq 'y')
}

function Test-MSADPTADConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [Parameter(Mandatory)]
        [string]$AdServer
    )

    Write-MSADPTLog -Message "Pre-flight: testing Active Directory connectivity to '$AdServer'." -Level 'INFO'

    try {
        $rootDSE = Get-ADRootDSE -Server $AdServer -Credential $Credential -ErrorAction Stop

        Write-MSADPTLog -Message "Pre-flight successful. Connected to '$($rootDSE.dnsHostName)'. DefaultNamingContext='$($rootDSE.defaultNamingContext)'." -Level 'INFO'
        return $rootDSE
    }
    catch {
        Write-MSADPTLog -Message "Pre-flight failed for '$AdServer': $($_.Exception.Message)" -Level 'ERROR'
        return $null
    }
}

function New-MSADPTAdCommandSplat {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [PSCredential]$Credential
    )

    $splat = @{}

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $splat.Server = $Server
    }

    if ($null -ne $Credential) {
        $splat.Credential = $Credential
    }

    return $splat
}

function Get-MSADPTRemoteRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [string]$SubKey,

        [Parameter(Mandatory)]
        [string]$ValueName
    )

    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            $ComputerName
        )

        if (-not $base) { return $null }

        $key = $base.OpenSubKey($SubKey)
        if (-not $key) { return $null }

        return $key.GetValue($ValueName, $null)
    }
    catch {
        return $null
    }
}

function Test-MSADPTWebEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [string]$RelativePath
    )

    $httpOpen  = $false
    $httpsOpen = $false

    foreach ($scheme in @('http', 'https')) {
        $uri = "${scheme}://$ComputerName/$RelativePath"

        try {
            $null = Invoke-WebRequest -Uri $uri -Method Head -MaximumRedirection 0 -TimeoutSec 5 -ErrorAction Stop
            if ($scheme -eq 'http')  { $httpOpen = $true }
            if ($scheme -eq 'https') { $httpsOpen = $true }
        }
        catch {
            if ($_.Exception.Response) {
                try {
                    $status = [int]$_.Exception.Response.StatusCode
                    if ($status -in 200,301,302,401,403) {
                        if ($scheme -eq 'http')  { $httpOpen = $true }
                        if ($scheme -eq 'https') { $httpsOpen = $true }
                    }
                }
                catch {
                    # ignore nested parse issues
                }
            }
        }
    }

    return [PSCustomObject]@{
        HttpOpen  = $httpOpen
        HttpsOpen = $httpsOpen
    }
}

#Export-ModuleMember -Function Write-MSADPTLog, Prompt-User, Test-MSADPTADConnectivity
Export-ModuleMember -Function Write-MSADPTLog, Prompt-User, Test-MSADPTADConnectivity, New-MSADPTAdCommandSplat, Get-MSADPTRemoteRegistryValue, Test-MSADPTWebEndpoint