Set-Location "C:\Users\cyberadmin\Desktop"

# Determine PSVersion once
$pv = $PSVersionTable.PSVersion
Write-Host "⚡Showing PowerShell version..." -ForegroundColor Green 
$PSVersionTable | Format-Table -AutoSize

Function Start-MyCommands {

    Write-Host "⚡Executing startup tasks..." -ForegroundColor Green
    #Ensure PSGallery exists and is trusted
    if (-not(Get-PSRepository -Name PSGallery -ErrorAction Continue)) {
        Register-PSRepository -Name PSGallery -SourceLocation 'https://www.powershellgallery.com/api/v2' -InstallationPolicy Trusted
    } else {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
    #Safer execution policy for user scope
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
	
	Write-Host "⚡Installing ...RSAT-AD-PowerShell" -ForegroundColor Green
	Install-WindowsFeature -Name RSAT-AD-PowerShell

	Write-Host "⚡Installing ...NuGet provider" -ForegroundColor Green 
	Install-PackageProvider -Name NuGet -Force -Scope AllUsers

	Write-Host "⚡Installing ...PowerShellGet" -ForegroundColor Green
	Install-Module -Name PowerShellGet -Force -Scope AllUsers
	
	Write-Host "⚡Installing ...PackageManagement" -ForegroundColor Green
	Install-Module -Name PackageManagement -Force -Scope AllUsers -AllowClobber

    Write-Host "⚡Installing ...AADInternals" -ForegroundColor Green
	Install-Module -Name AADInternals -Scope AllUsers -Force -AllowClobber
	
	Write-Host "⚡Installing ...AADInternals-Endpoints" -ForegroundColor Green
	Install-Module -Name 'AADInternals-Endpoints' -Scope AllUsers -Force -AllowClobber
	
	Write-Host "⚡Importing ...AADInternals" -ForegroundColor Green
	Import-Module AADInternals
	
	Write-Host "⚡Importing ...AADInternals-Endpoints" -ForegroundColor Green
	Import-Module 'AADInternals-Endpoints'

	Write-Host "⚡Add-WindowsCapability ...Rsat.ActiveDirectory" -ForegroundColor Green
	Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

	Write-Host "⚡Add-WindowsCapability ...Rsat.AD" -ForegroundColor Green
	Add-WindowsCapability -Online -Name Rsat.AD.PowerShell~~~~0.0.1.0

	Write-Host "⚡Importing ...ActiveDirectory" -ForegroundColor Green
	Import-Module ActiveDirectory

    Write-Host "⚡Listing Active Directory Module part of RSAT..." -ForegroundColor Green
    Get-Module ActiveDirectory -ListAvailable
	
    Write-Host "⚡Showing RSAT version..." -ForegroundColor Green
    Get-WindowsCapability -Name 'RSAT.ActiveDirectory*' -Online
	
	Write-Host "⚡Installing ...Az" -ForegroundColor Green
	Install-Module -Name Az -Scope AllUsers -AllowClobber -Force

    Write-Host "⚡Showing Azure PowerShell version..." -ForegroundColor Green
    Get-InstalledModule -Name Az | Format-Table -AutoSize
    Start-Sleep -Seconds 2

    Write-Host "⚡Installing ...DSInternals" -ForegroundColor Green
	Install-Module -Name DSInternals -Scope AllUsers -AllowClobber -Force
	
	Write-Host "⚡Importing ...DSInternals" -ForegroundColor Green
    Import-Module -Name DSInternals -ErrorAction Continue
		
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
			Import-Module -Name $psReflectPath -ErrorAction Continue
			Write-Host "⚡PSReflect loaded from $psReflectPath" -ForegroundColor Green
		} else {
			Write-Host ("⚡PSReflect module not found at: {0}" -f $psReflectPath) -ForegroundColor Yellow
		}

		#Import PowerView script by full path(dot - source.ps1 or Import-Module only for psm1 / dll)
		$powerViewPath = Join-Path -Path $scriptRoot -ChildPath 'PowerSploit\Recon\PowerView.ps1'
		if (Test-Path $powerViewPath) {
			.$powerViewPath #dot - source a script to import functions into session 
			Write-Host "⚡PowerView dot-sourced from $powerViewPath" -ForegroundColor Green
		} else {
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
				Update-Module -Name $name -Force -ErrorAction Continue
				Write-Host "⚡Updated $name" -ForegroundColor Green
			} catch {
				Write-Host ("⚡Failed {0}: {1}" -f $name, $_.Exception.Message) -ForegroundColor Yellow
			}
		}
	}
	
	if (Get-Command az -ErrorAction SilentlyContinue) {
		Write-Host "⚡Installing Azure Automation CLI extension" -ForegroundColor Green
		az extension add -n automation
		Write-Host "⚡Enables automatic, silent installation of missing CLI extensions when you run a command for the first time" -ForegroundColor Green
		az config set extension.use_dynamic_install=yes_without_prompt
	} else {
		Write-Host "Azure CLI (az) not found; skipping az extension commands" -ForegroundColor Yellow
	}

    Write-Host "⚡PowerView Runs much better in an older PS - RUN the following..." -ForegroundColor Green
    Write-Host "⚡powershell.exe -Version 5.1" -ForegroundColor Green
    Write-Host "⚡.\kickoff.ps1" -ForegroundColor Green
	Write-Host "⚡ PowerSploit\Recon> . .\PowerView.ps1" -ForegroundColor Green
	
	Get-AzContext

}
Start-MyCommands

Get-Module -Name AADInternals, AADInternals-Endpoints, DSInternals, ActiveDirectory, PSPreworkout, PSReflect, PowerView -ErrorAction SilentlyContinue
