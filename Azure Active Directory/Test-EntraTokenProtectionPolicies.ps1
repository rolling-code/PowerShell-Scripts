<#
.SYNOPSIS
    Read-only audit of Microsoft Entra Conditional Access Token Protection policies.

.DESCRIPTION
    Uses the existing Azure CLI sign-in context. It does not call Connect-MgGraph and
    does not request new Microsoft Graph consent.

    The script retrieves Conditional Access policy JSON through `az rest`, saves it
    locally, parses the local JSON, classifies native Token Protection and the browser-
    based Azure Resource Manager Token Protection preview, and exports a detailed CSV.

    No tenant settings are changed.

.VERSION
    2.1.0
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) 'TokenProtectionAudit'),
    [switch]$ForceAzureLogin
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-Section {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkGray
}
function Write-InfoLine { param([string]$Text) Write-Host "[INFO] $Text" -ForegroundColor Gray }
function Write-OkLine { param([string]$Text) Write-Host "[OK]   $Text" -ForegroundColor Green }
function Write-WarnLine { param([string]$Text) Write-Host "[WARN] $Text" -ForegroundColor Yellow }
function Write-FindLine { param([string]$Text) Write-Host "[FIND] $Text" -ForegroundColor Magenta }
function Write-FailLine { param([string]$Text) Write-Host "[FAIL] $Text" -ForegroundColor Red }

function Get-PropertyValue {
    param([AllowNull()]$Object,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-FlatList {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    return (@($Value) | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; '
}

function Test-ContainsValue {
    param([AllowNull()]$Collection,[Parameter(Mandatory)][string]$Value)
    return @($Collection | ForEach-Object { [string]$_ }) -contains $Value
}

function Resolve-ResourceName {
    param([Parameter(Mandatory)][string]$ResourceId)
    $known = @{
        'All'                                  = 'All cloud apps'
        'Office365'                            = 'Office 365 application suite'
        '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
        '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
        '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Microsoft Teams Services'
        '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Windows Azure Service Management API / Azure Resource Manager'
        '9cdead84-a844-4324-93f2-b2e6bb768d07' = 'Azure Virtual Desktop'
        '0af06dc6-e4b5-4f28-818e-e78e62d137a5' = 'Windows 365'
    }
    if ($known.ContainsKey($ResourceId)) { return $known[$ResourceId] }
    return $ResourceId
}

function Resolve-ResourceList {
    param([AllowNull()]$ResourceIds)
    $values = foreach ($id in @($ResourceIds)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$id)) {
            Resolve-ResourceName -ResourceId ([string]$id)
        }
    }
    return ConvertTo-FlatList $values
}

function Get-TokenProtectionControl {
    param([AllowNull()]$SessionControls)
    if ($null -eq $SessionControls) {
        return [pscustomobject]@{ Present=$false; Enabled=$false; Property=''; Raw='' }
    }

    # Current Microsoft Graph beta property for device-bound sign-in sessions.
    foreach ($name in @('secureSignInSession','signInTokenProtection','tokenProtection','binding')) {
        $value = Get-PropertyValue $SessionControls $name
        if ($null -ne $value) {
            $enabled = Get-PropertyValue $value 'isEnabled'
            if ($null -eq $enabled -and $value -is [bool]) { $enabled = $value }
            return [pscustomobject]@{
                Present  = $true
                Enabled  = ($enabled -eq $true)
                Property = $name
                Raw      = ($value | ConvertTo-Json -Depth 20 -Compress)
            }
        }
    }

    return [pscustomobject]@{ Present=$false; Enabled=$false; Property=''; Raw='' }
}

function Get-PolicyAssessment {
    param([Parameter(Mandatory)]$Policy)

    $conditions = Get-PropertyValue $Policy 'conditions'
    $apps = Get-PropertyValue $conditions 'applications'
    $users = Get-PropertyValue $conditions 'users'
    $platforms = Get-PropertyValue $conditions 'platforms'
    $sessions = Get-PropertyValue $Policy 'sessionControls'

    $includeApps = @(Get-PropertyValue $apps 'includeApplications')
    $excludeApps = @(Get-PropertyValue $apps 'excludeApplications')
    $clientTypes = @(Get-PropertyValue $conditions 'clientAppTypes')
    $includePlatforms = @(Get-PropertyValue $platforms 'includePlatforms')
    $excludePlatforms = @(Get-PropertyValue $platforms 'excludePlatforms')

    $includeUsers = @(Get-PropertyValue $users 'includeUsers')
    $excludeUsers = @(Get-PropertyValue $users 'excludeUsers')
    $includeGroups = @(Get-PropertyValue $users 'includeGroups')
    $excludeGroups = @(Get-PropertyValue $users 'excludeGroups')
    $includeRoles = @(Get-PropertyValue $users 'includeRoles')
    $excludeRoles = @(Get-PropertyValue $users 'excludeRoles')

    $control = Get-TokenProtectionControl $sessions

    $exchange = Test-ContainsValue $includeApps '00000002-0000-0ff1-ce00-000000000000'
    $sharepoint = Test-ContainsValue $includeApps '00000003-0000-0ff1-ce00-000000000000'
    $teams = Test-ContainsValue $includeApps '1fec8e78-bce4-4aaf-ab1b-5451cc387264'
    $avd = Test-ContainsValue $includeApps '9cdead84-a844-4324-93f2-b2e6bb768d07'
    $w365 = Test-ContainsValue $includeApps '0af06dc6-e4b5-4f28-818e-e78e62d137a5'
    $arm = Test-ContainsValue $includeApps '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    $allApps = Test-ContainsValue $includeApps 'All'
    $officeSuite = Test-ContainsValue $includeApps 'Office365'

    $nativeResource = $exchange -or $sharepoint -or $teams -or $avd -or $w365
    $nativeClient = Test-ContainsValue $clientTypes 'mobileAppsAndDesktopClients'
    $browserClient = Test-ContainsValue $clientTypes 'browser'
    $allClients = Test-ContainsValue $clientTypes 'all'
    $windows = Test-ContainsValue $includePlatforms 'windows'
    $mac = Test-ContainsValue $includePlatforms 'macOS'

    $nativePattern = $control.Enabled -and $nativeResource -and $nativeClient -and -not $browserClient
    $webPattern = $control.Enabled -and $arm -and $browserClient -and ($windows -or $mac)

    $workloads = New-Object System.Collections.Generic.List[string]
    if ($exchange) { [void]$workloads.Add('Exchange Online') }
    if ($sharepoint) { [void]$workloads.Add('SharePoint Online') }
    if ($teams) { [void]$workloads.Add('Microsoft Teams') }
    if ($avd) { [void]$workloads.Add('Azure Virtual Desktop') }
    if ($w365) { [void]$workloads.Add('Windows 365') }
    if ($arm) { [void]$workloads.Add('Azure Resource Manager web preview') }

    $classification = 'No Token Protection'
    $status = 'Not detected'
    $recommendation = 'No Token Protection session control detected. Keep this policy unchanged if unrelated, or create a separate report-only Token Protection pilot policy.'

    if ($control.Present -and -not $control.Enabled) {
        $classification = 'Token Protection control present but disabled'
        $status = 'Inconclusive'
        $recommendation = 'Review why the Token Protection session control is disabled. Use a separate report-only pilot before enforcement.'
    }
    elseif ($nativePattern -and $webPattern) {
        $classification = 'Mixed native and web-preview Token Protection'
        $status = 'Confirmed'
        $recommendation = 'Separate native and web-preview Token Protection into different policies so prerequisites, scope, reporting, and compatibility can be assessed independently.'
    }
    elseif ($nativePattern) {
        $classification = 'Native Windows Token Protection'
        $status = 'Confirmed'
        if ($Policy.state -eq 'enabled') {
            $recommendation = 'Native Token Protection is enforced. Confirm Bound status in interactive and non-interactive sign-in logs and review compatibility exclusions.'
        }
        elseif ($Policy.state -eq 'enabledForReportingButNotEnforced') {
            $recommendation = 'Native Token Protection is report-only. Review Bound and Unbound sign-in results before enforcement.'
        }
        else {
            $recommendation = 'Native Token Protection policy is disabled. Confirm pilot evidence and approval before enabling.'
        }
    }
    elseif ($webPattern) {
        $classification = 'Web-app Token Protection preview for ARM'
        $status = 'Confirmed'
        if ($Policy.state -eq 'enabled') {
            $recommendation = 'Web preview is enforced. Confirm supported ARM portals, OS/browser builds, extension deployment, platform authentication, and sign-in status codes.'
        }
        elseif ($Policy.state -eq 'enabledForReportingButNotEnforced') {
            $recommendation = 'Web preview is report-only. Review ARM browser sign-ins and unsupported web-app impact before enforcement.'
        }
        else {
            $recommendation = 'Web-preview policy is disabled. Confirm prerequisites and pilot readiness before enabling.'
        }
    }
    elseif ($control.Enabled) {
        $classification = 'Token Protection enabled with nonstandard or incomplete targeting'
        $status = 'Likely'
        $issues = New-Object System.Collections.Generic.List[string]
        if (-not $nativeResource -and -not $arm) { [void]$issues.Add('no recognized supported resource selected') }
        if ($allApps -or $officeSuite) { [void]$issues.Add('broad All/Office365 targeting can include unsupported resources') }
        if ($allClients) { [void]$issues.Add('all client app types selected') }
        if ($browserClient -and -not $arm) { [void]$issues.Add('browser selected without ARM web-preview resource') }
        if ($arm -and -not $browserClient) { [void]$issues.Add('ARM selected without browser client targeting') }
        if ($arm -and -not ($windows -or $mac)) { [void]$issues.Add('ARM preview lacks explicit Windows/macOS platform targeting') }
        if ($issues.Count -eq 0) { [void]$issues.Add('targeting does not match a documented native or web-preview pattern') }
        $recommendation = 'Review targeting: ' + ($issues -join '; ') + '. Prefer separate report-only native and web-preview policies.'
    }

    [pscustomobject]@{
        PolicyName = [string]$Policy.displayName
        PolicyId = [string]$Policy.id
        State = [string]$Policy.state
        CreatedDateTime = [string]$Policy.createdDateTime
        ModifiedDateTime = [string]$Policy.modifiedDateTime
        TokenProtectionPresent = $control.Present
        TokenProtectionEnabled = $control.Enabled
        TokenProtectionProperty = $control.Property
        Classification = $classification
        FindingStatus = $status
        ProtectedWorkloads = ($workloads -join '; ')
        NativePatternMatched = $nativePattern
        WebPreviewPatternMatched = $webPattern
        TargetsExchangeOnline = $exchange
        TargetsSharePointOnline = $sharepoint
        TargetsMicrosoftTeams = $teams
        TargetsAzureVirtualDesktop = $avd
        TargetsWindows365 = $w365
        TargetsAzureResourceManager = $arm
        TargetsAllCloudApps = $allApps
        TargetsOffice365Suite = $officeSuite
        IncludedResources = Resolve-ResourceList $includeApps
        ExcludedResources = Resolve-ResourceList $excludeApps
        ClientAppTypes = ConvertTo-FlatList $clientTypes
        IncludedPlatforms = ConvertTo-FlatList $includePlatforms
        ExcludedPlatforms = ConvertTo-FlatList $excludePlatforms
        IncludedUsers = ConvertTo-FlatList $includeUsers
        ExcludedUsers = ConvertTo-FlatList $excludeUsers
        IncludedGroups = ConvertTo-FlatList $includeGroups
        ExcludedGroups = ConvertTo-FlatList $excludeGroups
        IncludedRoles = ConvertTo-FlatList $includeRoles
        ExcludedRoles = ConvertTo-FlatList $excludeRoles
        SessionControlsRaw = if ($null -ne $sessions) { $sessions | ConvertTo-Json -Depth 30 -Compress } else { '' }
        TokenProtectionRaw = $control.Raw
        Recommendation = $recommendation
    }
}

# Required first two output lines.
Write-Host '[1/2] Looking for Native Token Protection policies for Windows native clients accessing Exchange Online, SharePoint Online, Microsoft Teams, Azure Virtual Desktop, or Windows 365.' -ForegroundColor Cyan
Write-Host '[2/2] Looking for the new Token Protection web-app preview for browser access to Azure Resource Manager through the Windows Azure Service Management API.' -ForegroundColor Cyan

Write-Section 'Microsoft Entra Token Protection Conditional Access Audit'
Write-InfoLine 'Read-only: uses the existing Azure CLI sign-in context and makes only Microsoft Graph GET requests.'
Write-InfoLine 'No Connect-MgGraph call is used, and no new Graph consent request is initiated.'

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI was not found. Install Azure CLI, then sign in with az login using an already authorized account.'
}

Write-Section 'Validating Azure CLI context'
if ($ForceAzureLogin) {
    Write-WarnLine 'ForceAzureLogin was specified. Azure CLI will open its normal sign-in flow.'
    az login | Out-Null
}

$accountJson = az account show --output json 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "No usable Azure CLI sign-in was found. Run az login first. Azure CLI response: $accountJson"
}

$account = $accountJson | ConvertFrom-Json
Write-OkLine "Azure CLI signed in as: $($account.user.name)"
Write-OkLine "Tenant: $($account.tenantId)"
if ($account.name) { Write-InfoLine "Current Azure subscription context: $($account.name)" }

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$rawJsonPath = Join-Path $OutputDirectory "ConditionalAccessPolicies-Raw-$timestamp.json"
$csvPath = Join-Path $OutputDirectory "TokenProtection-ConditionalAccess-Audit-$timestamp.csv"
$summaryPath = Join-Path $OutputDirectory "TokenProtection-Audit-Summary-$timestamp.txt"

Write-Section 'Retrieving Conditional Access policy JSON'
Write-InfoLine 'Calling Microsoft Graph beta through az rest. This does not request additional delegated scopes.'

$uri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies?$top=100'
$policies = @()
$pageNumber = 0

try {
    do {
        $pageNumber++
        Write-InfoLine "Retrieving policy page $pageNumber..."
        $responseJson = az rest --method GET --url $uri --output json 2>&1
        if ($LASTEXITCODE -ne 0) {
            $message = ($responseJson | Out-String).Trim()
            throw "Azure CLI could not read Conditional Access policies. No approval request was submitted. The current Azure CLI identity/client might lack existing authorization or the required directory role. Details: $message"
        }

        $responseText = ($responseJson | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($responseText)) {
            throw "Azure CLI returned an empty response for policy page $pageNumber."
        }

        try {
            $response = $responseText | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "Azure CLI returned data that could not be parsed as JSON on page $pageNumber. Response: $responseText"
        }

        $pagePolicies = @(Get-PropertyValue $response 'value')
        if ($pagePolicies.Count -gt 0) {
            $policies += $pagePolicies
            Write-OkLine "Page $pageNumber returned $($pagePolicies.Count) policies. Running total: $($policies.Count)"
        }
        else {
            Write-WarnLine "Page $pageNumber returned no policies."
        }

        $uri = [string](Get-PropertyValue $response '@odata.nextLink')
    } while (-not [string]::IsNullOrWhiteSpace($uri))
}
catch {
    Write-FailLine $_.Exception.Message
    throw
}

$policyJson = $policies | ConvertTo-Json -Depth 100
if ([string]::IsNullOrWhiteSpace($policyJson)) {
    throw 'No Conditional Access policy JSON was produced.'
}
$policyJson | Set-Content $rawJsonPath -Encoding UTF8
Write-OkLine "Retrieved $($policies.Count) policies."
Write-OkLine "Saved raw JSON: $rawJsonPath"

Write-Section 'Parsing saved JSON locally'
$localPolicies = @(Get-Content $rawJsonPath -Raw | ConvertFrom-Json)
Write-InfoLine "Locally loaded $($localPolicies.Count) policies from the saved JSON file."
$report = @(foreach ($policy in $localPolicies) { Get-PolicyAssessment $policy })
$report = @($report | Sort-Object @{Expression={if ($_.TokenProtectionEnabled) {0}else{1}}}, Classification, PolicyName)
$report | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
Write-OkLine "Saved detailed CSV: $csvPath"

$native = @($report | Where-Object NativePatternMatched -eq $true)
$web = @($report | Where-Object WebPreviewPatternMatched -eq $true)
$nonstandard = @($report | Where-Object { $_.TokenProtectionEnabled -and -not $_.NativePatternMatched -and -not $_.WebPreviewPatternMatched })
$without = @($report | Where-Object TokenProtectionPresent -eq $false)

Write-Section 'Detailed policy results'
foreach ($row in $report) {
    if ($row.NativePatternMatched) {
        Write-OkLine "$($row.PolicyName): Native Token Protection; state=$($row.State); workloads=$($row.ProtectedWorkloads)"
    }
    elseif ($row.WebPreviewPatternMatched) {
        Write-OkLine "$($row.PolicyName): Web-app Token Protection preview; state=$($row.State); workloads=$($row.ProtectedWorkloads)"
    }
    elseif ($row.TokenProtectionEnabled) {
        Write-FindLine "$($row.PolicyName): Token Protection enabled with nonstandard/incomplete targeting."
        Write-WarnLine $row.Recommendation
    }
    else {
        Write-InfoLine "$($row.PolicyName): No enabled Token Protection session control."
    }
}

Write-Section 'Summary'
Write-Host "Policies reviewed:                $($report.Count)" -ForegroundColor White
Write-Host "Native Token Protection:          $($native.Count)" -ForegroundColor $(if ($native.Count) {'Green'} else {'Yellow'})
Write-Host "Web-app preview Token Protection: $($web.Count)" -ForegroundColor $(if ($web.Count) {'Green'} else {'Yellow'})
Write-Host "Nonstandard Token Protection:      $($nonstandard.Count)" -ForegroundColor $(if ($nonstandard.Count) {'Magenta'} else {'Green'})
Write-Host "Without Token Protection:          $($without.Count)" -ForegroundColor Gray

@(
    'Microsoft Entra Token Protection Conditional Access Audit'
    "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
    "TenantId: $($account.tenantId)"
    "AzureCliUser: $($account.user.name)"
    "PoliciesReviewed: $($report.Count)"
    "NativeTokenProtectionPolicies: $($native.Count)"
    "WebPreviewTokenProtectionPolicies: $($web.Count)"
    "NonstandardTokenProtectionPolicies: $($nonstandard.Count)"
    "PoliciesWithoutTokenProtection: $($without.Count)"
    "RawJson: $rawJsonPath"
    "DetailedCsv: $csvPath"
) | Set-Content $summaryPath -Encoding UTF8

Write-OkLine "Saved summary: $summaryPath"
if ($native.Count -eq 0) { Write-WarnLine 'No policy matched the documented native Windows Token Protection pattern.' }
if ($web.Count -eq 0) { Write-WarnLine 'No policy matched the documented ARM browser Token Protection preview pattern.' }
if ($nonstandard.Count -gt 0) { Write-FindLine 'Review nonstandard Token Protection policies in the CSV before changing anything.' }

Write-Host ''
Write-Host 'Completed. No tenant settings were changed.' -ForegroundColor Green
Write-Host "CSV report: $csvPath" -ForegroundColor Green
Write-Host "Raw JSON:  $rawJsonPath" -ForegroundColor Green
