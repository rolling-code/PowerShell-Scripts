#requires -RunAsAdministrator

<#
.SYNOPSIS
    Disables Windows Defender Firewall and Windows Defender Antivirus.
.DESCRIPTION
    This script disables critical Windows security features. 
#>

# Disable Windows Defender Firewall for all profiles
Write-Host "Disabling Windows Defender Firewall..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Write-Host "Windows Defender Firewall disabled for all profiles." -ForegroundColor Green

# Stop and disable Windows Defender services
Write-Host "Disabling Windows Defender services..." -ForegroundColor Yellow
$services = @(
    "WinDefend"           # Windows Defender Antivirus Service
    "Sense"               # Windows Defender Advanced Threat Protection
    "WdNisSvc"            # Windows Defender Network Inspection Service
    "WdNisDrv"            # Windows Defender Network Inspection Driver
    "WdBoot"              # Windows Defender Boot Driver
    "WdFilter"            # Windows Defender Filter Driver
)

foreach ($service in $services) {
    try {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "  -> ${service}: Stopped and disabled" -ForegroundColor Green
    }
    catch {
        Write-Warning "  -> ${service}: $($_.Exception.Message)"
    }
}

# Disable Windows Defender via registry (real-time protection)
Write-Host "Disabling Windows Defender real-time protection..." -ForegroundColor Yellow
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender"
)

foreach ($regPath in $regPaths) {
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -ErrorAction SilentlyContinue
}

# Disable real-time monitoring
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Write-Host "Windows Defender real-time monitoring disabled." -ForegroundColor Green
}
catch {
    Write-Warning "Failed to disable real-time monitoring: $($_.Exception.Message)"
}

# Disable tamper protection (Windows 10 1903+, Windows 11)
Write-Host "Attempting to disable tamper protection..." -ForegroundColor Yellow
$tpPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
if (Test-Path $tpPath) {
    Set-ItemProperty -Path $tpPath -Name "TamperProtection" -Value 4 -Type DWord
    Write-Host "Tamper protection disabled." -ForegroundColor Green
}

Write-Host "`n[!] Security features have been disabled." -ForegroundColor Red
Write-Host "Remember to re-enable protections after testing." -ForegroundColor Yellow