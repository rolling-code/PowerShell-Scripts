Set-Location "C:\Users\mcontestabile\foo"

# Determine PSVersion once
$pv = $PSVersionTable.PSVersion
Write-Host "⚡Showing PowerShell version..." -ForegroundColor Green 
$PSVersionTable | Format-Table -AutoSize

Function Start-MyCommands {

    Write-Host "⚡Executing startup tasks..." -ForegroundColor Green
    #Ensure PSGallery exists and is trusted
    if (-not(Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
        Register-PSRepository -Name PSGallery -SourceLocation 'https://www.powershellgallery.com/api/v2' -InstallationPolicy Trusted
    } else {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
    #Safer execution policy for user scope
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force

    #Update PowerShellGet / PackageManagement to avoid missing parameter issues
    try {
        Install-Module -Name PowerShellGet -Force -Scope CurrentUser -ErrorAction Stop
    } catch {
        #Write-Verbose "⚡PowerShellGet update skipped: $($_.Exception.Message)" -ForegroundColor Green 
		Write-Host ("⚡PowerShellGet update skipped: {0}" -f $_.Exception.Message) -ForegroundColor Green
    }
    try {
        Install-Module -Name PackageManagement -Force -Scope CurrentUser -ErrorAction Stop
    } catch {
        #Write-Verbose "⚡PackageManagement update skipped: $($_.Exception.Message)" -ForegroundColor Yellow
		Write-Host ("⚡PackageManagement update skipped: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }

    Write-Host "⚡Ensuring AADInternals and AADInternals-Endpoints present and up to date..." -ForegroundColor Green
    $modules =  @('AADInternals', 'AADInternals-Endpoints')
	foreach($m in $modules) {
		$installed = Get-InstalledModule -Name $m -ErrorAction SilentlyContinue
		if (-not $installed) {
			Write-Host "⚡Installing $m" -ForegroundColor Green
			Install-Module -Name $m -Scope CurrentUser -Force -ErrorAction Stop
		} else {
			$remote = Find-Module -Name $m -ErrorAction SilentlyContinue
			if ($remote -and ($remote.Version -gt $installed.Version)) {
				Write-Host "⚡Updating $m (local $($installed.Version) -> remote $($remote.Version))" -ForegroundColor Green
				Update-Module -Name $m -Force -ErrorAction Stop
			} else {
				Write-Host "⚡$m is up to date" -ForegroundColor Green
			}
		}
		Import-Module -Name $m -ErrorAction Stop
    }
	# install the AD GUI+tools capability (includes ADUC)
	Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

	# install the AD PowerShell module (if separate on your build)
	Add-WindowsCapability -Online -Name Rsat.AD.PowerShell~~~~0.0.1.0

	# load the module into the current session
	Import-Module ActiveDirectory


    Write-Host "⚡Listing Active Directory Module part of RSAT..." -ForegroundColor Green
    Get-Module ActiveDirectory -ListAvailable
    Write-Host "⚡Showing RSAT version..." -ForegroundColor Green
    Get-WindowsCapability -Name 'RSAT.ActiveDirectory*' -Online

    Write-Host "⚡Showing Azure PowerShell version..." -ForegroundColor Green
    Get-InstalledModule -Name Az | Format-Table -AutoSize
    Start-Sleep -Seconds 2

    Write-Host "⚡Installing or updating DSInternals..." -ForegroundColor Green
    if (-not(Get-InstalledModule -Name DSInternals -ErrorAction SilentlyContinue)) {
        Install-Module -Name DSInternals -Scope CurrentUser -Force -ErrorAction Stop
    } else {
        $local = Get-InstalledModule -Name DSInternals
        $remote = Find-Module -Name DSInternals -ErrorAction SilentlyContinue
        if ($remote -and($remote.Version -gt $local.Version)) {
            Update-Module -Name DSInternals -Force -ErrorAction Stop
        }
    }
    #Wait for availability with timeout
    $timeout = 30;
    $elapsed = 0
	while (-not(Get-Module -Name DSInternals -ListAvailable) -and($elapsed -lt $timeout)) {
		Write-Host "⚡Waiting for DSInternals to become available..." -ForegroundColor Yellow
		Start-Sleep -Seconds 2;
		$elapsed += 2
	}
    if ($elapsed -ge $timeout) {
        Write-Warning "⚡Timeout waiting for DSInternals module" -ForegroundColor Yellow
    }
    Import-Module -Name DSInternals -ErrorAction SilentlyContinue
		
	if ($pv.Major -ge 7) {
		# PowerShell 7 or later
		Write-Host "⚡Running PowerShell $($pv.ToString()) — using PowerShell 7+ path not loading PowerSploit" -ForegroundColor Green
	}elseif ($pv.Major -eq 5 -and $pv.Minor -eq 1) {
		# Exactly Windows PowerShell 5.1
		Write-Host "⚡Running Windows PowerShell $($pv.ToString()) — using 5.1 path - loading PSReflect and PowerSploit" -ForegroundColor Green

		#Import PSReflect by absolute path relative to script location
		$scriptRoot = if ($PSScriptRoot) {
			$PSScriptRoot
		} else {
			$PWD.Path
		}
		$psReflectPath = Join-Path -Path $scriptRoot -ChildPath 'PSReflect\PSReflect.psm1'
		if (Test-Path $psReflectPath) {
			Import-Module -Name $psReflectPath -ErrorAction Stop
			Write-Host "⚡PSReflect loaded from $psReflectPath" -ForegroundColor Green
		} else {
			#Write-Warning "⚡PSReflect module not found at $psReflectPath" -ForegroundColor Yellow
			Write-Host ("⚡PSReflect module not found at: {0}" -f $psReflectPath) -ForegroundColor Yellow
		}

		#Import PowerView script by full path(dot - source.ps1 or Import-Module only for psm1 / dll)
		$powerViewPath = Join-Path -Path $scriptRoot -ChildPath 'PowerSploit\Recon\PowerView.ps1'
		if (Test-Path $powerViewPath) {
			.$powerViewPath #dot - source a script to import functions into session 
			Write-Host "⚡PowerView dot-sourced from $powerViewPath" -ForegroundColor Green
		} else {
			#Write-Warning "⚡PowerView not found at $powerViewPath" -ForegroundColor Yellow
			Write-Host ("⚡PowerView module not found at: {0}" -f $powerViewPath) -ForegroundColor Yellow
		}
	}else{
		# Any other PowerShell version
		# Write-Host "⚡Running PowerShell $($pv.ToString()) — using fallback path - not loading PowerSploit" -ForegroundColor Yellow
		# place fallback code here
	}

	Write-Host "⚡Installing PSPreworkout" -ForegroundColor Green
	Install-Module -Name PSPreworkout -Scope CurrentUser -Force -AllowClobber
	Write-Host "⚡Checking for updates" -ForegroundColor Green
	Get-ModulesWithUpdate -PassThru
	
	$response = Read-Host "Apply module updates? (Y/N)"
	if ($response.ToUpper() -eq 'Y') {
		Write-Host "⚡Applying updates" -ForegroundColor Green
		Get-InstalledModule | ForEach-Object {
			$name = $_.Name
			try {
				Update-Module -Name $name -Force -ErrorAction Stop
				Write-Host "⚡Updated $name" -ForegroundColor Green
			} catch {
				Write-Host ("⚡Failed {0}: {1}" -f $name, $_.Exception.Message) -ForegroundColor Yellow
			}
		}
	}

    Write-Host "⚡PowerView Runs much better in an older PS - RUN the following..." -ForegroundColor Green
    Write-Host "⚡powershell.exe -Version 5.1" -ForegroundColor Green
    Write-Host "⚡.\kickoff.ps1" -ForegroundColor Green
	Write-Host "⚡ PowerSploit\Recon> . .\PowerView.ps1" -ForegroundColor Green

}
Start-MyCommands

Get-Module -Name AADInternals, AADInternals-Endpoints, DSInternals, ActiveDirectory, PSPreworkout, PSReflect, PowerView -ErrorAction SilentlyContinue

