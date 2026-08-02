<#
.SYNOPSIS
Performs a read-only security configuration audit of one Azure App Service Web App or Function App.

.DESCRIPTION
Collects configuration evidence for a single Microsoft.Web/sites resource by using the Azure CLI.
The script evaluates transport security, public ingress, access restrictions, authentication metadata,
managed identity, deployment authentication, application-setting names, Key Vault references,
diagnostic settings, App Service plan metadata, deployment slots, network integration, and resource-scope
RBAC assignments.

Secret values, connection-string values, publishing profiles, publishing passwords, access tokens, and
Kudu content are never requested or displayed. The audit makes no Azure configuration changes.

Each check is classified as PASS, FAIL, REVIEW, INFO, NOT_APPLICABLE, NOT_AUTHORIZED, or ERROR.
FAIL is reserved for deterministic undesirable configuration. Context-dependent controls are REVIEW.

The script writes timestamped CSV, JSON, and text-summary evidence files unless -NoExport is specified.

.PARAMETER SubscriptionId
Subscription containing the target application.

.PARAMETER ResourceGroup
Resource group containing the target application.

.PARAMETER AppName
Azure App Service Web App or Function App name.

.PARAMETER OutputDirectory
Directory for timestamped audit exports. Defaults to the current directory.

.PARAMETER IncludeInheritedRoleAssignments
Includes RBAC assignments inherited from parent scopes. Without this switch, only assignments returned
for the exact Web App scope are reported.

.PARAMETER TestPublicEndpoint
Performs unauthenticated HTTP HEAD requests to the default hostname and custom hostnames. This is an
external reachability observation only and does not test application authorization or exploitability.

.PARAMETER PublicEndpointTimeoutSeconds
Timeout for each optional public endpoint request. Defaults to 15 seconds.

.PARAMETER NoExport
Displays findings without writing CSV, JSON, and text-summary files.

.EXAMPLE
.\Inspect-AzWebAppSecurity-Consolidated.ps1 `
    -SubscriptionId "00000000-0000-0000-0000-000000000000" `
    -ResourceGroup "rg-application" `
    -AppName "contoso-api"

.EXAMPLE
.\Inspect-AzWebAppSecurity-Consolidated.ps1 `
    -SubscriptionId "00000000-0000-0000-0000-000000000000" `
    -ResourceGroup "rg-application" `
    -AppName "contoso-api" `
    -IncludeInheritedRoleAssignments `
    -TestPublicEndpoint `
    -OutputDirectory ".\WebAppAudit"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$AppName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Get-Location).Path,

    [Parameter()]
    [switch]$IncludeInheritedRoleAssignments,

    [Parameter()]
    [switch]$TestPublicEndpoint,

    [Parameter()]
    [ValidateRange(3, 120)]
    [int]$PublicEndpointTimeoutSeconds = 15,

    [Parameter()]
    [switch]$NoExport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SubscriptionId = $SubscriptionId.Trim()
$ResourceGroup = $ResourceGroup.Trim()
$AppName = $AppName.Trim()
$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:Evidence = [ordered]@{}

function Invoke-AzCliJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Operation,
        [switch]$AllowFailure
    )

    $outputFile = [System.IO.Path]::GetTempFileName()
    $errorFile = [System.IO.Path]::GetTempFileName()
    try {
        & az @Arguments --only-show-errors --output json 1> $outputFile 2> $errorFile
        $exitCode = $LASTEXITCODE
        $raw = if (Test-Path -LiteralPath $outputFile) { Get-Content -LiteralPath $outputFile -Raw } else { $null }
        $errorText = if (Test-Path -LiteralPath $errorFile) { Get-Content -LiteralPath $errorFile -Raw } else { $null }

        if ($exitCode -ne 0) {
            if ($AllowFailure) {
                return [pscustomobject]@{ Succeeded = $false; Data = $null; Error = $errorText.Trim(); Operation = $Operation }
            }
            throw "Azure CLI operation failed: $Operation. $($errorText.Trim())"
        }

        $data = $null
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            try { $data = $raw | ConvertFrom-Json -Depth 100 }
            catch { throw "Azure CLI returned invalid JSON for '$Operation': $($_.Exception.Message)" }
        }
        return [pscustomobject]@{ Succeeded = $true; Data = $data; Error = $null; Operation = $Operation }
    }
    finally {
        Remove-Item -LiteralPath $outputFile, $errorFile -Force -ErrorAction SilentlyContinue
    }
}

function Add-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL','REVIEW','INFO','NOT_APPLICABLE','NOT_AUTHORIZED','ERROR')][string]$Status,
        [Parameter(Mandatory)][string]$ObservedValue,
        [Parameter(Mandatory)][string]$Rationale,
        [Parameter()][string]$Recommendation = ''
    )
    $script:Findings.Add([pscustomobject][ordered]@{
        TimestampUtc   = [datetime]::UtcNow.ToString('o')
        SubscriptionId = $SubscriptionId
        ResourceGroup  = $ResourceGroup
        AppName        = $AppName
        Category       = $Category
        Check          = $Check
        Status         = $Status
        ObservedValue  = $ObservedValue
        Rationale      = $Rationale
        Recommendation = $Recommendation
    })
}

function Get-PropertyValue {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-CollectionValue {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$Object,
        [Parameter()][string]$WrapperProperty = 'value'
    )

    if ($null -eq $Object) { return @() }

    $wrapper = $Object.PSObject.Properties[$WrapperProperty]
    if ($null -ne $wrapper) {
        if ($null -eq $wrapper.Value) { return @() }
        return @($wrapper.Value)
    }

    # Azure CLI commands are inconsistent: some return { value: [...] },
    # while others return the array directly. Normalize both shapes.
    if ($Object -is [System.Collections.IEnumerable] -and $Object -isnot [string]) {
        return @($Object)
    }

    return @($Object)
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) was not found in PATH. Install Azure CLI and authenticate with az login.'
}

$account = Invoke-AzCliJson -Arguments @('account','show') -Operation 'Read active Azure CLI account'
if (-not $account.Data -or -not $account.Data.id) {
    throw 'No active Azure CLI context was found. Run az login first.'
}

$setSubscription = Invoke-AzCliJson -Arguments @('account','set','--subscription',$SubscriptionId) -Operation 'Set subscription context'
$activeAccount = (Invoke-AzCliJson -Arguments @('account','show') -Operation 'Validate subscription context').Data
if ([string]$activeAccount.id -ne $SubscriptionId) {
    throw "Azure CLI did not switch to subscription '$SubscriptionId'."
}

$resourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$AppName"
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$safeAppName = $AppName -replace '[^A-Za-z0-9._-]', '_'

Write-Host "Auditing $resourceId" -ForegroundColor Cyan
Write-Host "Azure identity: $($activeAccount.user.name) | Subscription: $($activeAccount.name)" -ForegroundColor DarkCyan
Write-Host 'Read-only mode: secret values and publishing credentials will not be requested.' -ForegroundColor Green

$siteResult = Invoke-AzCliJson -Arguments @('resource','show','--ids',$resourceId,'--api-version','2023-12-01') -Operation 'Read Web App resource'
$site = $siteResult.Data
if (-not $site) { throw "Web App '$AppName' was not found at the supplied resource group and subscription." }
$script:Evidence.Site = $site

$kind = [string]$site.kind
$isFunctionApp = $kind -match 'functionapp'
$targetIsLinux = $kind -match 'linux'
$isContainer = $kind -match 'container'
$properties = $site.properties
$defaultHostName = [string](Get-PropertyValue $properties 'defaultHostName')
$enabledHostNames = @((Get-PropertyValue $properties 'enabledHostNames') | Where-Object { $_ })
$customHostNames = @($enabledHostNames | Where-Object { $_ -notmatch '\.azurewebsites\.net$' -and $_ -notmatch '\.scm\.azurewebsites\.net$' })

Add-Finding -Category 'Inventory' -Check 'Resource discovered' -Status 'INFO' -ObservedValue "Kind=$kind; State=$($properties.state); Location=$($site.location)" -Rationale 'Target resource was resolved by its exact Azure resource ID.'
Add-Finding -Category 'Inventory' -Check 'Default hostname' -Status 'INFO' -ObservedValue $defaultHostName -Rationale 'Default App Service hostname reported by Azure Resource Manager.'
Add-Finding -Category 'Inventory' -Check 'Custom hostnames' -Status 'INFO' -ObservedValue $(if ($customHostNames.Count) { $customHostNames -join '; ' } else { '(none observed)' }) -Rationale 'Custom hostnames can expand the externally reachable attack surface.'

$httpsOnly = Get-PropertyValue $properties 'httpsOnly'
if ($httpsOnly -eq $true) {
    Add-Finding 'Transport' 'HTTPS only' 'PASS' 'Enabled' 'HTTP requests are configured for HTTPS redirection.'
} else {
    Add-Finding 'Transport' 'HTTPS only' 'FAIL' ([string]$httpsOnly) 'The application is not configured to require HTTPS.' 'Enable HTTPS Only after validating application compatibility.'
}

$publicNetworkAccess = [string](Get-PropertyValue $properties 'publicNetworkAccess')
if ($publicNetworkAccess -eq 'Disabled') {
    Add-Finding 'Network' 'Public network access' 'PASS' $publicNetworkAccess 'Public network access is explicitly disabled.'
} elseif ($publicNetworkAccess -eq 'Enabled') {
    Add-Finding 'Network' 'Public network access' 'REVIEW' $publicNetworkAccess 'Public network access is enabled; effective exposure also depends on access restrictions and private connectivity.' 'Validate that public ingress is required and restricted to approved sources or a fronting service.'
} else {
    Add-Finding 'Network' 'Public network access' 'REVIEW' $(if ($publicNetworkAccess) { $publicNetworkAccess } else { '(not explicitly reported)' }) 'Azure did not report an explicit disabled state. Effective exposure requires access-restriction review.'
}

$configResult = Invoke-AzCliJson -Arguments @('webapp','config','show','--resource-group',$ResourceGroup,'--name',$AppName) -Operation 'Read site configuration' -AllowFailure
if ($configResult.Succeeded) {
    $config = $configResult.Data
    $script:Evidence.SiteConfig = $config

    $minTls = [string](Get-PropertyValue $config 'minTlsVersion')
    if ($minTls -in @('1.2','1.3')) { Add-Finding 'Transport' 'Minimum TLS version' 'PASS' $minTls 'The main endpoint requires TLS 1.2 or later.' }
    elseif ($minTls) { Add-Finding 'Transport' 'Minimum TLS version' 'FAIL' $minTls 'The main endpoint permits a TLS version below 1.2.' 'Set the minimum TLS version to 1.2 or later.' }
    else { Add-Finding 'Transport' 'Minimum TLS version' 'REVIEW' '(not reported)' 'The minimum TLS version could not be determined from site configuration.' }

    $scmMinTls = [string](Get-PropertyValue $config 'scmMinTlsVersion')
    if ($scmMinTls -in @('1.2','1.3')) { Add-Finding 'Transport' 'SCM minimum TLS version' 'PASS' $scmMinTls 'The deployment endpoint requires TLS 1.2 or later.' }
    elseif ($scmMinTls) { Add-Finding 'Transport' 'SCM minimum TLS version' 'FAIL' $scmMinTls 'The SCM endpoint permits a TLS version below 1.2.' 'Set SCM minimum TLS to 1.2 or later.' }
    else { Add-Finding 'Transport' 'SCM minimum TLS version' 'REVIEW' '(not reported)' 'The SCM minimum TLS version was not reported.' }

    $ftpsState = [string](Get-PropertyValue $config 'ftpsState')
    if ($ftpsState -eq 'Disabled') { Add-Finding 'Deployment' 'FTP/FTPS state' 'PASS' $ftpsState 'FTP-based deployment is disabled.' }
    elseif ($ftpsState -eq 'FtpsOnly') { Add-Finding 'Deployment' 'FTP/FTPS state' 'REVIEW' $ftpsState 'Encrypted FTPS remains enabled and creates a credential-based deployment surface.' 'Disable FTP/FTPS if it is not operationally required.' }
    else { Add-Finding 'Deployment' 'FTP/FTPS state' 'FAIL' $(if ($ftpsState) { $ftpsState } else { '(not reported)' }) 'Unencrypted FTP may be permitted or the setting is indeterminate.' 'Set FTPS state to Disabled, or at minimum FtpsOnly when explicitly required.' }

    $http20 = Get-PropertyValue $config 'http20Enabled'
    Add-Finding 'Transport' 'HTTP/2' 'INFO' ([string]$http20) 'HTTP/2 is a capability observation, not a security boundary or authorization control.'

    $remoteDebug = Get-PropertyValue $config 'remoteDebuggingEnabled'
    if ($remoteDebug -eq $true) { Add-Finding 'Runtime' 'Remote debugging' 'FAIL' 'Enabled' 'Remote debugging increases the administrative attack surface.' 'Disable remote debugging outside a time-bounded troubleshooting window.' }
    else { Add-Finding 'Runtime' 'Remote debugging' 'PASS' 'Disabled' 'Remote debugging is not enabled.' }

    $alwaysOn = Get-PropertyValue $config 'alwaysOn'
    $alwaysStatus = if ($isFunctionApp) { 'INFO' } elseif ($alwaysOn -eq $true) { 'PASS' } else { 'REVIEW' }
    Add-Finding 'Availability' 'Always On' $alwaysStatus ([string]$alwaysOn) 'Always On is workload and App Service plan dependent; it is not universally required for Function Apps.'
} else {
    Add-Finding 'Coverage' 'Site configuration' 'NOT_AUTHORIZED' $configResult.Error 'The current identity could not retrieve site configuration.' 'Review Reader-equivalent access and rerun.'
}

$authResult = Invoke-AzCliJson -Arguments @('webapp','auth','show','--resource-group',$ResourceGroup,'--name',$AppName) -Operation 'Read App Service authentication configuration' -AllowFailure
if ($authResult.Succeeded) {
    $auth = $authResult.Data
    $script:Evidence.Authentication = $auth
    $authEnabled = Get-PropertyValue $auth 'enabled'
    $unauthenticatedAction = [string](Get-PropertyValue $auth 'unauthenticatedClientAction')
    if ($authEnabled -eq $true) {
        Add-Finding 'Authentication' 'App Service Authentication' 'INFO' "Enabled; UnauthenticatedAction=$unauthenticatedAction" 'Platform authentication is enabled. Application-specific authorization still requires separate validation.'
    } else {
        Add-Finding 'Authentication' 'App Service Authentication' 'REVIEW' 'Disabled' 'Platform authentication is disabled. This may be valid when the application implements its own authentication or is intentionally public.' 'Validate the intended authentication architecture and test application-layer authorization separately.'
    }
} else {
    Add-Finding 'Coverage' 'App Service Authentication' 'NOT_AUTHORIZED' $authResult.Error 'Authentication configuration could not be retrieved.'
}

$identityResult = Invoke-AzCliJson -Arguments @('webapp','identity','show','--resource-group',$ResourceGroup,'--name',$AppName) -Operation 'Read managed identity' -AllowFailure
if ($identityResult.Succeeded -and $identityResult.Data) {
    $identity = $identityResult.Data
    $script:Evidence.Identity = $identity
    $identityType = [string](Get-PropertyValue $identity 'type')
    Add-Finding 'Identity' 'Managed identity' 'INFO' $(if ($identityType) { $identityType } else { 'None' }) 'Managed identity presence is contextual. Its downstream permissions must be reviewed separately.'
} else {
    Add-Finding 'Identity' 'Managed identity' 'INFO' 'None or not returned' 'A managed identity is not universally required. No failure is assigned without a demonstrated dependency.'
}

$basicAuthResult = Invoke-AzCliJson -Arguments @('rest','--method','get','--uri',"https://management.azure.com$resourceId/basicPublishingCredentialsPolicies?api-version=2023-12-01") -Operation 'Read basic publishing authentication policies' -AllowFailure
if ($basicAuthResult.Succeeded -and $basicAuthResult.Data) {
    $script:Evidence.BasicPublishingCredentialPolicies = $basicAuthResult.Data
    $policies = @(Get-CollectionValue -Object $basicAuthResult.Data)
    foreach ($policy in $policies) {
        $policyName = [string](Get-PropertyValue $policy 'name')
        $policyProperties = Get-PropertyValue $policy 'properties'
        $allow = Get-PropertyValue $policyProperties 'allow'
        if ($allow -eq $true) { Add-Finding 'Deployment' "Basic publishing authentication: $policyName" 'FAIL' 'Allowed' 'Basic username/password publishing authentication is enabled.' 'Disable the basic publishing credentials policy when deployment tooling supports modern authentication.' }
        else { Add-Finding 'Deployment' "Basic publishing authentication: $policyName" 'PASS' 'Disallowed' 'Basic publishing authentication is disabled.' }
    }

    $ftpPolicy = @($policies | Where-Object { (Get-PropertyValue $_ 'name') -eq 'ftp' } | Select-Object -First 1)
    if ($ftpPolicy.Count -gt 0) {
        $ftpPolicyAllow = Get-PropertyValue (Get-PropertyValue $ftpPolicy[0] 'properties') 'allow'
        if ($ftpsState -ne 'Disabled' -and $ftpPolicyAllow -eq $false) {
            foreach ($ftpFinding in @($script:Findings | Where-Object { $_.Category -eq 'Deployment' -and $_.Check -eq 'FTP/FTPS state' })) {
                $ftpFinding.Status = 'INFO'
                $ftpFinding.ObservedValue = "$ftpsState; BasicPublishingAuthentication=Disallowed"
                $ftpFinding.Rationale = 'The FTPS protocol setting is present, but the FTP basic publishing credential policy is disallowed. Credential-based FTP/FTPS publishing is therefore not enabled by this configuration.'
                $ftpFinding.Recommendation = 'Optionally set FTPS state to Disabled for configuration clarity if no deployment workflow depends on it.'
            }
        }
    }
} else {
    Add-Finding 'Coverage' 'Basic publishing authentication policies' 'NOT_AUTHORIZED' $basicAuthResult.Error 'The policies could not be retrieved. No publishing credentials were requested.'
}

Add-Finding 'Secrets' 'Application settings and connection strings' 'NOT_APPLICABLE' 'Values not requested by this audit' 'Azure CLI list operations return secret-bearing values together with metadata. This safe default does not call those operations, preventing secret values from entering the process or evidence files.' 'Review secret storage through an approved privileged workflow, or add a separately controlled metadata-only method when Azure exposes one.'

$accessResult = Invoke-AzCliJson -Arguments @('webapp','config','access-restriction','show','--resource-group',$ResourceGroup,'--name',$AppName) -Operation 'Read access restrictions' -AllowFailure
if ($accessResult.Succeeded) {
    $access = $accessResult.Data
    $script:Evidence.AccessRestrictions = $access
    $mainRestrictionData = @(Get-CollectionValue -Object (Get-PropertyValue $access 'ipSecurityRestrictions'))
    $mainRules = @($mainRestrictionData | Where-Object { (Get-PropertyValue $_ 'name') -ne 'Allow all' -and [int](Get-PropertyValue $_ 'priority') -lt 2147483647 })
    $scmRestrictionData = @(Get-CollectionValue -Object (Get-PropertyValue $access 'scmIpSecurityRestrictions'))
    $scmRules = @($scmRestrictionData | Where-Object { (Get-PropertyValue $_ 'name') -ne 'Allow all' -and [int](Get-PropertyValue $_ 'priority') -lt 2147483647 })
    $mainDefault = [string](Get-PropertyValue $access 'ipSecurityRestrictionsDefaultAction')
    $scmDefault = [string](Get-PropertyValue $access 'scmIpSecurityRestrictionsDefaultAction')
    $mainAllowAll = @($mainRestrictionData | Where-Object { (Get-PropertyValue $_ 'ipAddress') -eq 'Any' -and (Get-PropertyValue $_ 'action') -eq 'Allow' }).Count -gt 0
    $scmAllowAll = @($scmRestrictionData | Where-Object { (Get-PropertyValue $_ 'ipAddress') -eq 'Any' -and (Get-PropertyValue $_ 'action') -eq 'Allow' }).Count -gt 0
    $mainEffectiveDefault = if ($mainDefault) { $mainDefault } elseif ($mainAllowAll) { 'Allow' } else { 'NotReported' }
    $scmEffectiveDefault = if ($scmDefault) { $scmDefault } elseif ($scmAllowAll) { 'Allow' } else { 'NotReported' }
    $mainStatus = if ($publicNetworkAccess -eq 'Disabled') { 'PASS' } elseif ($mainEffectiveDefault -eq 'Deny' -or $mainRules.Count -gt 0) { 'PASS' } else { 'REVIEW' }
    $scmUsesMain = Get-PropertyValue $access 'scmIpSecurityRestrictionsUseMain'
    $scmStatus = if ($publicNetworkAccess -eq 'Disabled') { 'PASS' } elseif ($scmUsesMain -eq $true -and $mainStatus -eq 'PASS') { 'PASS' } elseif ($scmEffectiveDefault -eq 'Deny' -or $scmRules.Count -gt 0) { 'PASS' } else { 'REVIEW' }
    Add-Finding 'Network' 'Main-site access restrictions' $mainStatus "ExplicitRules=$($mainRules.Count); EffectiveDefaultAction=$mainEffectiveDefault; AllowAll=$mainAllowAll" 'Access restrictions help constrain public ingress. An effective Allow default means the site is network-reachable unless another control blocks it.' 'If public access is not required, disable it or apply reviewed allow rules with a deny default.'
    Add-Finding 'Network' 'SCM access restrictions' $scmStatus "ExplicitRules=$($scmRules.Count); EffectiveDefaultAction=$scmEffectiveDefault; AllowAll=$scmAllowAll; UsesMainSiteRules=$scmUsesMain" 'The SCM endpoint is a distinct administrative surface unless it inherits restrictive main-site rules.' 'Restrict SCM separately or configure it to inherit reviewed main-site restrictions.'
} else {
    Add-Finding 'Coverage' 'Access restrictions' 'NOT_AUTHORIZED' $accessResult.Error 'Access restriction configuration could not be retrieved.'
}

$privateEndpointsResult = Invoke-AzCliJson -Arguments @('rest','--method','get','--uri',"https://management.azure.com$resourceId/privateEndpointConnections?api-version=2023-12-01") -Operation 'Read private endpoint connections' -AllowFailure
if ($privateEndpointsResult.Succeeded) {
    $privateEndpoints = @(Get-CollectionValue -Object $privateEndpointsResult.Data)
    $script:Evidence.PrivateEndpointConnections = $privateEndpoints
    Add-Finding 'Network' 'Private endpoint connections' 'INFO' "Count=$($privateEndpoints.Count)" 'Private endpoints are architecture dependent and do not by themselves disable public ingress.'
} else {
    Add-Finding 'Coverage' 'Private endpoint connections' 'NOT_AUTHORIZED' $privateEndpointsResult.Error 'Private endpoint connections could not be retrieved.'
}

$vnetResult = Invoke-AzCliJson -Arguments @('webapp','vnet-integration','list','--resource-group',$ResourceGroup,'--name',$AppName) -Operation 'Read VNet integration' -AllowFailure
if ($vnetResult.Succeeded) {
    $vnets = @($vnetResult.Data)
    $script:Evidence.VNetIntegration = $vnets
    Add-Finding 'Network' 'Outbound VNet integration' 'INFO' "Count=$($vnets.Count)" 'VNet integration affects outbound application connectivity; it is not equivalent to private inbound access.'
} else {
    Add-Finding 'Coverage' 'VNet integration' 'NOT_AUTHORIZED' $vnetResult.Error 'VNet integration could not be retrieved.'
}

$diagResult = Invoke-AzCliJson -Arguments @('monitor','diagnostic-settings','list','--resource',$resourceId) -Operation 'Read diagnostic settings' -AllowFailure
if ($diagResult.Succeeded) {
    $diagnostics = @(Get-CollectionValue -Object $diagResult.Data)
    $script:Evidence.DiagnosticSettings = $diagnostics
    $destinations = @($diagnostics | ForEach-Object { @((Get-PropertyValue $_ 'workspaceId'), (Get-PropertyValue $_ 'storageAccountId'), (Get-PropertyValue $_ 'eventHubAuthorizationRuleId'), (Get-PropertyValue $_ 'marketplacePartnerId')) } | Where-Object { $_ })
    Add-Finding 'Logging' 'Azure Monitor diagnostic settings' $(if ($diagnostics.Count -gt 0 -and $destinations.Count -gt 0) { 'PASS' } else { 'REVIEW' }) "Settings=$($diagnostics.Count); Destinations=$($destinations.Count)" 'Diagnostic settings provide control-plane configured log routing, but retention and alert coverage require separate validation.' 'Configure an approved destination and validate required categories, retention, and detections.'
} else {
    Add-Finding 'Coverage' 'Diagnostic settings' 'NOT_AUTHORIZED' $diagResult.Error 'Diagnostic settings could not be retrieved.'
}

$planId = [string](Get-PropertyValue $properties 'serverFarmId')
if ($planId) {
    $planResult = Invoke-AzCliJson -Arguments @('resource','show','--ids',$planId,'--api-version','2023-12-01') -Operation 'Read App Service plan' -AllowFailure
    if ($planResult.Succeeded) {
        $plan = $planResult.Data
        $script:Evidence.AppServicePlan = $plan
        Add-Finding 'Hosting' 'App Service plan' 'INFO' "Name=$(Get-PropertyValue $plan 'name'); SKU=$(Get-PropertyValue (Get-PropertyValue $plan 'sku') 'name'); Tier=$(Get-PropertyValue (Get-PropertyValue $plan 'sku') 'tier'); Kind=$(Get-PropertyValue $plan 'kind')" 'Plan tier is a capacity and architecture observation; Premium is not universally required.'
    } else { Add-Finding 'Coverage' 'App Service plan' 'NOT_AUTHORIZED' $planResult.Error 'The plan could not be retrieved.' }
}

$slotsResult = Invoke-AzCliJson -Arguments @('webapp','deployment','slot','list','--resource-group',$ResourceGroup,'--name',$AppName) -Operation 'Read deployment slots' -AllowFailure
if ($slotsResult.Succeeded) {
    $slots = @($slotsResult.Data)
    $script:Evidence.DeploymentSlots = $slots
    Add-Finding 'Deployment' 'Deployment slots' 'INFO' "Count=$($slots.Count); Names=$((@($slots | ForEach-Object { Get-PropertyValue $_ 'name' })) -join '; ')" 'Slots are workload dependent. Each slot should be audited separately because configuration and exposure can differ.'
} else {
    Add-Finding 'Coverage' 'Deployment slots' 'NOT_AUTHORIZED' $slotsResult.Error 'Deployment slots could not be retrieved.'
}

$roleArgs = @('role','assignment','list','--scope',$resourceId)
if ($IncludeInheritedRoleAssignments) { $roleArgs += '--include-inherited' }
$rolesResult = Invoke-AzCliJson -Arguments $roleArgs -Operation 'Read RBAC assignments' -AllowFailure
if ($rolesResult.Succeeded) {
    $roles = @(Get-CollectionValue -Object $rolesResult.Data)
    $roleMetadata = @(
        foreach ($role in $roles) {
            [pscustomobject]@{
                PrincipalType     = Get-PropertyValue $role 'principalType'
                PrincipalName     = Get-PropertyValue $role 'principalName'
                PrincipalId       = Get-PropertyValue $role 'principalId'
                RoleDefinitionName = Get-PropertyValue $role 'roleDefinitionName'
                Scope             = Get-PropertyValue $role 'scope'
            }
        }
    )
    $script:Evidence.RoleAssignments = $roleMetadata
    $highRoleNames = @('Owner','Contributor','User Access Administrator','Website Contributor')
    $resourcePrefix = $resourceId.TrimEnd('/')
    $resourceGroupScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $directHighRoles = @($roleMetadata | Where-Object {
        (Get-PropertyValue $_ 'RoleDefinitionName') -in $highRoleNames -and
        ([string](Get-PropertyValue $_ 'Scope')).TrimEnd('/') -ieq $resourcePrefix
    })
    $resourceGroupHighRoles = @($roleMetadata | Where-Object {
        (Get-PropertyValue $_ 'RoleDefinitionName') -in $highRoleNames -and
        ([string](Get-PropertyValue $_ 'Scope')).TrimEnd('/') -ieq $resourceGroupScope
    })
    $parentHighRoles = @($roleMetadata | Where-Object {
        (Get-PropertyValue $_ 'RoleDefinitionName') -in $highRoleNames -and
        ([string](Get-PropertyValue $_ 'Scope')).TrimEnd('/') -ine $resourcePrefix -and
        ([string](Get-PropertyValue $_ 'Scope')).TrimEnd('/') -ine $resourceGroupScope
    })
    $uniqueRoleNames = @(
        $roleMetadata |
            ForEach-Object { Get-PropertyValue $_ 'RoleDefinitionName' } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Sort-Object -Unique
    )
    $roleSummary = if ($uniqueRoleNames.Count -gt 0) { $uniqueRoleNames -join '; ' } else { '(none returned at this scope)' }
    $rbacStatus = if ($directHighRoles.Count -gt 0 -or $resourceGroupHighRoles.Count -gt 0) { 'REVIEW' } else { 'INFO' }
    Add-Finding 'Authorization' 'Effective RBAC assignments' $rbacStatus "Total=$($roleMetadata.Count); DirectHighImpact=$($directHighRoles.Count); ResourceGroupHighImpact=$($resourceGroupHighRoles.Count); ParentHighImpact=$($parentHighRoles.Count); Roles=$roleSummary" 'Direct and resource-group high-impact grants are app-proximate. Subscription and management-group grants are inherited governance context and are reported separately to avoid misrepresenting them as app-specific assignments.' 'Review direct and resource-group high-impact principals first; audit broader inherited roles once per parent scope rather than once per application.'
} else {
    Add-Finding 'Coverage' 'RBAC assignments' 'NOT_AUTHORIZED' $rolesResult.Error 'RBAC assignments could not be listed.'
}

if ($isContainer) {
    $containerResult = Invoke-AzCliJson -Arguments @('webapp','config','container','show','--resource-group',$ResourceGroup,'--name',$AppName) -Operation 'Read container configuration' -AllowFailure
    if ($containerResult.Succeeded) {
        $container = $containerResult.Data
        $safeContainerMetadata = [ordered]@{}
        foreach ($property in $container.PSObject.Properties) {
            if ($property.Name -match '(?i)(password|secret|token|key)') { continue }
            $safeContainerMetadata[$property.Name] = $property.Value
        }
        $script:Evidence.ContainerMetadata = $safeContainerMetadata
        $containerText = ($safeContainerMetadata | ConvertTo-Json -Depth 20 -Compress)
        $mutableTag = $containerText -match '(?i):latest(?:"|\s|$)'
        Add-Finding 'Supply Chain' 'Container image reference' $(if ($mutableTag) { 'REVIEW' } else { 'INFO' }) $(if ($mutableTag) { 'Mutable :latest tag observed' } else { 'No :latest tag observed in non-secret metadata' }) 'A tag is not equivalent to an immutable digest. Registry provenance and image scanning require separate validation.' 'Prefer immutable image digests for controlled production deployments where supported.'
    } else { Add-Finding 'Coverage' 'Container configuration' 'NOT_AUTHORIZED' $containerResult.Error 'Container metadata could not be retrieved.' }
} else {
    Add-Finding 'Supply Chain' 'Container image reference' 'NOT_APPLICABLE' "Kind=$kind" 'The target is not identified as an App Service custom-container workload.'
}

if ($TestPublicEndpoint) {
    $hostsToTest = @($defaultHostName) + $customHostNames | Where-Object { $_ } | Sort-Object -Unique
    foreach ($hostName in $hostsToTest) {
        $uri = "https://$hostName/"
        try {
            $response = Invoke-WebRequest -Uri $uri -Method Head -MaximumRedirection 0 -TimeoutSec $PublicEndpointTimeoutSeconds -SkipHttpErrorCheck -ErrorAction Stop
            $endpointCode = [int]$response.StatusCode
            $endpointStatus = if ($endpointCode -ge 200 -and $endpointCode -lt 400) { 'REVIEW' } else { 'INFO' }
            Add-Finding 'External Observation' "HTTPS endpoint: $hostName" $endpointStatus "HTTP $endpointCode" 'A successful HTTP response confirms public network reachability from this vantage point. It does not by itself prove unauthorized access to protected functions or data.' 'Validate expected anonymous routes and function-level authorization separately.'
        } catch {
            $statusCode = $null
            if ($_.Exception.Response) { try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {} }
            if ($statusCode) { Add-Finding 'External Observation' "HTTPS endpoint: $hostName" 'INFO' "HTTP $statusCode" 'The endpoint responded. Authentication and authorization require separate testing.' }
            else { Add-Finding 'External Observation' "HTTPS endpoint: $hostName" 'INFO' "No HTTP response: $($_.Exception.Message)" 'The request failed from the current network vantage point; this does not prove the endpoint is globally unreachable.' }
        }
    }
} else {
    Add-Finding 'External Observation' 'Public endpoint request' 'NOT_APPLICABLE' 'Not requested' 'Use -TestPublicEndpoint to perform non-invasive unauthenticated HTTPS HEAD observations.'
}

$coverageGaps = @($script:Findings | Where-Object Status -in @('NOT_AUTHORIZED','ERROR'))
$script:Findings.Add([pscustomobject][ordered]@{
    TimestampUtc   = [datetime]::UtcNow.ToString('o')
    SubscriptionId = $SubscriptionId
    ResourceGroup  = $ResourceGroup
    AppName        = $AppName
    Category       = 'Coverage'
    Check          = 'Audit completeness'
    Status         = if ($coverageGaps.Count -eq 0) { 'PASS' } else { 'REVIEW' }
    ObservedValue  = "CoverageGaps=$($coverageGaps.Count)"
    Rationale      = if ($coverageGaps.Count -eq 0) { 'All requested control-plane checks returned a conclusive result.' } else { 'One or more controls could not be conclusively evaluated. The application cannot be declared fully reviewed from this run alone.' }
    Recommendation = if ($coverageGaps.Count -eq 0) { '' } else { 'Resolve or independently validate each NOT_AUTHORIZED or ERROR result before assigning a final application disposition.' }
})

$statusOrder = @{ FAIL=1; ERROR=2; REVIEW=3; NOT_AUTHORIZED=4; PASS=5; INFO=6; NOT_APPLICABLE=7 }
$sortedFindings = @($script:Findings | Sort-Object @{Expression={$statusOrder[$_.Status]}}, Category, Check)

Write-Host "`n=== Finding summary ===" -ForegroundColor Cyan
$sortedFindings | Group-Object Status | Sort-Object @{Expression={$statusOrder[$_.Name]}} | ForEach-Object {
    Write-Host ("{0,-16} {1,4}" -f $_.Name, $_.Count)
}

Write-Host "`n=== Findings requiring attention ===" -ForegroundColor Cyan
$attention = @($sortedFindings | Where-Object Status -in @('FAIL','ERROR','REVIEW','NOT_AUTHORIZED'))
if ($attention.Count) {
    $attention | Select-Object Status, Category, Check, ObservedValue | Format-Table -AutoSize -Wrap
} else {
    Write-Host 'No FAIL, ERROR, REVIEW, or NOT_AUTHORIZED findings were recorded.' -ForegroundColor Green
}

if (-not $NoExport) {
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
    $baseName = "WebAppSecurityAudit-$safeAppName-$timestamp"
    $csvPath = Join-Path $OutputDirectory "$baseName-Findings.csv"
    $jsonPath = Join-Path $OutputDirectory "$baseName-Evidence.json"
    $summaryPath = Join-Path $OutputDirectory "$baseName-Summary.txt"

    $sortedFindings | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8

    $exportObject = [ordered]@{
        AuditMetadata = [ordered]@{
            GeneratedUtc = [datetime]::UtcNow.ToString('o')
            AzureIdentity = [string]$activeAccount.user.name
            TenantId = [string]$activeAccount.tenantId
            SubscriptionId = $SubscriptionId
            SubscriptionName = [string]$activeAccount.name
            ResourceId = $resourceId
            ScriptVersion = '2.1.0'
            SecretValuesExported = $false
            PublishingCredentialsRequested = $false
        }
        Evidence = $script:Evidence
        Findings = $sortedFindings
    }
    $exportObject | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $jsonPath -Encoding utf8

    $summaryLines = @(
        'Azure App Service Security Audit',
        "Generated (UTC): $([datetime]::UtcNow.ToString('o'))",
        "Resource: $resourceId",
        "Kind: $kind",
        "Default hostname: $defaultHostName",
        "Secret values exported: False",
        "Publishing credentials requested: False",
        '',
        'Status counts:'
    )
    foreach ($group in ($sortedFindings | Group-Object Status | Sort-Object @{Expression={$statusOrder[$_.Name]}})) {
        $summaryLines += ("  {0}: {1}" -f $group.Name, $group.Count)
    }
    $summaryLines += @('', 'Attention findings:')
    foreach ($finding in $attention) {
        $summaryLines += ("  [{0}] {1} / {2}: {3}" -f $finding.Status, $finding.Category, $finding.Check, $finding.ObservedValue)
    }
    $summaryLines | Set-Content -LiteralPath $summaryPath -Encoding utf8

    Write-Host "`nEvidence written:" -ForegroundColor Green
    Write-Host " - $csvPath"
    Write-Host " - $jsonPath"
    Write-Host " - $summaryPath"
}

$sortedFindings
