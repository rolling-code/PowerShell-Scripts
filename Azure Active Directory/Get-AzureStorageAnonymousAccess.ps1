#requires -Version 7.0
<#
.SYNOPSIS
Audits Azure Storage accounts and blob container ACLs for anonymous public access.

.DESCRIPTION
Performs a read-only audit across accessible Azure subscriptions. The script reads
storage account settings through Azure Resource Manager, enumerates container ACLs
with Get-AzRmStorageContainer, classifies effective anonymous access, and exports
account-level and container-level CSV reports. It does not request storage keys,
generate SAS tokens, or modify Azure resources.

.PARAMETER StorageAccountName
Optional storage account names to audit. When omitted, all storage accounts in the
selected subscription scope are audited.

.PARAMETER CurrentSubscriptionOnly
Audits only the currently selected Azure subscription.

.PARAMETER OutputDirectory
Directory in which CSV reports are written.

.EXAMPLE
./Get-AzureStorageAnonymousAccess.ps1

.EXAMPLE
./Get-AzureStorageAnonymousAccess.ps1 -StorageAccountName acmepublicassets,acmeappstorage

.EXAMPLE
./Get-AzureStorageAnonymousAccess.ps1 -CurrentSubscriptionOnly -OutputDirectory ./audit-output
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string[]]$StorageAccountName,

    [Parameter()]
    [switch]$CurrentSubscriptionOnly,

    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD 'AzureStorageAnonymousAccessAudit')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($commandName in @(
    'Connect-AzAccount',
    'Get-AzContext',
    'Get-AzSubscription',
    'Set-AzContext',
    'Get-AzStorageAccount',
    'Get-AzRmStorageContainer'
)) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command '$commandName' was not found. Install or update Az.Accounts and Az.Storage."
    }
}

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Connect-AzAccount | Out-Null
}

New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null

$rawSubscriptions = if ($CurrentSubscriptionOnly) {
    @((Get-AzContext).Subscription)
}
else {
    @(Get-AzSubscription | Where-Object State -eq 'Enabled')
}

$subscriptions = @(
    foreach ($subscription in $rawSubscriptions) {
        $subscriptionId = if (-not [string]::IsNullOrWhiteSpace([string]$subscription.Id)) {
            [string]$subscription.Id
        }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$subscription.SubscriptionId)) {
            [string]$subscription.SubscriptionId
        }
        else {
            $null
        }

        if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
            Write-Warning "Skipping subscription '$($subscription.Name)' because no subscription ID was returned."
            continue
        }

        [pscustomobject]@{
            Name = [string]$subscription.Name
            Id   = $subscriptionId
        }
    }
)

if ($subscriptions.Count -eq 0) {
    throw 'No accessible Azure subscriptions with valid subscription IDs were returned.'
}

$requestedNames = @{}
foreach ($name in @($StorageAccountName)) {
    if (-not [string]::IsNullOrWhiteSpace($name)) {
        $requestedNames[$name.ToLowerInvariant()] = $true
    }
}

$accountResults = [System.Collections.Generic.List[object]]::new()
$containerResults = [System.Collections.Generic.List[object]]::new()
$foundNames = @{}

Write-Host "Auditing Azure Storage across $($subscriptions.Count) subscription(s)..." -ForegroundColor Cyan

foreach ($subscription in $subscriptions) {
    try {
        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
        $accounts = @(Get-AzStorageAccount -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not enumerate subscription '$($subscription.Name)': $($_.Exception.Message)"
        continue
    }

    foreach ($account in $accounts) {
        $accountName = [string]$account.StorageAccountName
        $accountKey = $accountName.ToLowerInvariant()

        if ($requestedNames.Count -gt 0 -and -not $requestedNames.ContainsKey($accountKey)) {
            continue
        }

        $foundNames[$accountKey] = $true
        $allowBlobPublicAccess = $account.AllowBlobPublicAccess
        $publicNetworkAccess = if ($null -eq $account.PublicNetworkAccess) { 'NotSet' } else { [string]$account.PublicNetworkAccess }
        $networkDefaultAction = if ($null -eq $account.NetworkRuleSet.DefaultAction) { 'NotSet' } else { [string]$account.NetworkRuleSet.DefaultAction }
        $containers = @()
        $enumerationStatus = 'Succeeded'
        $enumerationError = $null

        try {
            $containers = @(
                Get-AzRmStorageContainer `
                    -ResourceGroupName $account.ResourceGroupName `
                    -StorageAccountName $accountName `
                    -ErrorAction Stop
            )
        }
        catch {
            $enumerationStatus = 'Failed'
            $enumerationError = $_.Exception.Message
        }

        $publicContainerCount = 0

        foreach ($container in $containers) {
            $publicAccess = if ([string]::IsNullOrWhiteSpace([string]$container.PublicAccess)) {
                'None'
            }
            else {
                [string]$container.PublicAccess
            }

            $isPublicAcl = $publicAccess -in @('Blob', 'Container')
            $effectiveAnonymousRead = ($allowBlobPublicAccess -eq $true) -and $isPublicAcl
            $anonymousEnumeration = ($allowBlobPublicAccess -eq $true) -and ($publicAccess -eq 'Container')

            if ($effectiveAnonymousRead) {
                $publicContainerCount++
            }

            $containerResults.Add([pscustomobject]@{
                SubscriptionName        = $subscription.Name
                SubscriptionId          = $subscription.Id
                ResourceGroup           = $account.ResourceGroupName
                StorageAccountName      = $accountName
                ContainerName           = [string]$container.Name
                ContainerPublicAccess   = $publicAccess
                AllowBlobPublicAccess   = $allowBlobPublicAccess
                PublicNetworkAccess     = $publicNetworkAccess
                EffectiveAnonymousRead  = $effectiveAnonymousRead
                AnonymousEnumeration    = $anonymousEnumeration
                BlobEndpoint            = "https://${accountName}.blob.core.windows.net/$($container.Name)/"
            })
        }

        $risk = if ($enumerationStatus -eq 'Failed') {
            'Unknown-ContainerAclUnavailable'
        }
        elseif ($allowBlobPublicAccess -eq $false) {
            'BlockedAtAccountLevel'
        }
        elseif ($allowBlobPublicAccess -eq $true -and $publicContainerCount -gt 0) {
            'ConfirmedAnonymousAccessByConfiguration'
        }
        elseif ($allowBlobPublicAccess -eq $true) {
            'PermittedAtAccountNoPublicContainerFound'
        }
        else {
            'Review-AccountSettingNotExplicit'
        }

        $accountResults.Add([pscustomobject]@{
            SubscriptionName          = $subscription.Name
            SubscriptionId            = $subscription.Id
            ResourceGroup             = $account.ResourceGroupName
            StorageAccountName        = $accountName
            Location                  = [string]$account.Location
            Kind                      = [string]$account.Kind
            AllowBlobPublicAccess     = $allowBlobPublicAccess
            PublicNetworkAccess       = $publicNetworkAccess
            NetworkDefaultAction      = $networkDefaultAction
            ContainerEnumeration      = $enumerationStatus
            TotalContainers           = if ($enumerationStatus -eq 'Succeeded') { $containers.Count } else { $null }
            PublicContainers          = if ($enumerationStatus -eq 'Succeeded') { $publicContainerCount } else { $null }
            EffectiveAnonymousBlobRisk = $risk
            Error                     = $enumerationError
        })
    }
}

foreach ($name in $requestedNames.Keys) {
    if (-not $foundNames.ContainsKey($name)) {
        $accountResults.Add([pscustomobject]@{
            SubscriptionName           = $null
            SubscriptionId             = $null
            ResourceGroup              = $null
            StorageAccountName         = $name
            Location                   = $null
            Kind                       = $null
            AllowBlobPublicAccess      = $null
            PublicNetworkAccess        = $null
            NetworkDefaultAction       = $null
            ContainerEnumeration       = 'NotRun'
            TotalContainers            = $null
            PublicContainers           = $null
            EffectiveAnonymousBlobRisk = 'Unknown-NotFoundOrNoRBAC'
            Error                      = 'The account was not found in accessible subscriptions.'
        })
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$accountCsv = Join-Path $OutputDirectory "StorageAccountAnonymousAccessSummary-$timestamp.csv"
$containerCsv = Join-Path $OutputDirectory "StorageContainerPublicAccessDetails-$timestamp.csv"

$accountResults |
    Sort-Object EffectiveAnonymousBlobRisk, SubscriptionName, StorageAccountName |
    Export-Csv -Path $accountCsv -NoTypeInformation -Encoding utf8

$containerResults |
    Sort-Object @{ Expression = 'EffectiveAnonymousRead'; Descending = $true }, SubscriptionName, StorageAccountName, ContainerName |
    Export-Csv -Path $containerCsv -NoTypeInformation -Encoding utf8

$confirmedAccounts = @($accountResults | Where-Object EffectiveAnonymousBlobRisk -eq 'ConfirmedAnonymousAccessByConfiguration')
$publicContainers = @($containerResults | Where-Object EffectiveAnonymousRead -eq $true)
$enumerableContainers = @($containerResults | Where-Object AnonymousEnumeration -eq $true)
$unknownAccounts = @($accountResults | Where-Object EffectiveAnonymousBlobRisk -like 'Unknown-*')

Write-Host ''
Write-Host '=== Azure Storage Anonymous Access Audit ===' -ForegroundColor Cyan
Write-Host "Accounts audited                 : $($accountResults.Count)"
Write-Host "Accounts with anonymous access   : $($confirmedAccounts.Count)" -ForegroundColor $(if ($confirmedAccounts.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "Containers with anonymous reads  : $($publicContainers.Count)" -ForegroundColor $(if ($publicContainers.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "Anonymously enumerable containers: $($enumerableContainers.Count)" -ForegroundColor $(if ($enumerableContainers.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "Unknown or inaccessible accounts : $($unknownAccounts.Count)" -ForegroundColor Yellow
Write-Host ''

$accountResults |
    Format-Table StorageAccountName, AllowBlobPublicAccess, PublicNetworkAccess, TotalContainers, PublicContainers, EffectiveAnonymousBlobRisk -AutoSize

Write-Host "Account report  : $accountCsv" -ForegroundColor Cyan
Write-Host "Container report: $containerCsv" -ForegroundColor Cyan
Write-Host 'Read-only audit complete. No Azure settings were changed.' -ForegroundColor Green
