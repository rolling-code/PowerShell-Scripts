#requires -Version 5.1
<#
.SYNOPSIS
Audits delegated OAuth consent grants for one Microsoft Entra application.

.DESCRIPTION
Resolves an application by application client ID, retrieves its delegated OAuth2 permission grants,
expands each space-delimited scope into an individual record, identifies high-risk delegated scopes,
distinguishes tenant-wide consent from user-specific consent, and inventories application owners and
enterprise application assignments.

The script is read-only. It reuses the current Microsoft Graph session, requests no new consent,
installs no modules, and does not disconnect the session.

.PARAMETER TargetAppId
Application client ID of the application to audit.

.PARAMETER OutputPath
Directory for timestamped CSV and JSON reports. Defaults to the script directory.

.PARAMETER HighRiskScopes
Optional replacement list for the built-in delegated-scope risk catalog. When supplied, each custom
scope is classified as High severity and Custom category.

.EXAMPLE
.\Audit-AppDelegationRisks.ps1 -TargetAppId 'd586270a-ba25-43c7-a710-c5bea434fddb'

.EXAMPLE
.\Audit-AppDelegationRisks.ps1 -TargetAppId '36e899a8-29fe-402b-abeb-d4f3535e702f' -OutputPath .\Reports

.NOTES
Requires an existing Microsoft Graph PowerShell session and Get-MgContext plus
Invoke-MgGraphRequest from Microsoft.Graph.Authentication. Typical visibility uses previously
consented Application.Read.All and Directory.Read.All. The script never requests additional consent.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TargetAppId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter()]
    [AllowEmptyCollection()]
    [string[]]$HighRiskScopes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-OptionalProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$DefaultValue = ''
    )
    if ($null -eq $InputObject) { return $DefaultValue }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $DefaultValue }
    return $property.Value
}

function ConvertTo-NormalizedId {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value).Trim().Trim('{}').ToLowerInvariant()
}

function ConvertTo-SafeFileName {
    param([Parameter(Mandatory)][string]$Value)
    $safe = $Value
    foreach ($character in [System.IO.Path]::GetInvalidFileNameChars()) {
        $safe = $safe.Replace([string]$character, '_')
    }
    $safe = ($safe -replace '\s+', '-').Trim('-').Trim()
    if ([string]::IsNullOrWhiteSpace($safe)) { return 'application' }
    return $safe
}

function ConvertTo-UtcText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return '' }
    try { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    catch { return [string]$Value }
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri -OutputType PSObject
        $valueProperty = $response.PSObject.Properties['value']
        if ($null -ne $valueProperty) {
            foreach ($item in @($valueProperty.Value)) {
                if ($null -ne $item) { $items.Add($item) }
            }
        } elseif ($null -ne $response) {
            $items.Add($response)
        }
        $nextUri = [string](Get-OptionalProperty $response '@odata.nextLink')
    }
    return $items.ToArray()
}

function Invoke-OptionalGraphCollection {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$DataSet,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Warnings
    )
    try { return @(Get-GraphCollection -Uri $Uri) }
    catch {
        $message = "$DataSet could not be retrieved: $($_.Exception.Message)"
        $Warnings.Add([pscustomobject]@{ DataSet=$DataSet; Message=$message })
        Write-Warning $message
        return @()
    }
}

function Export-CsvWithHeaders {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string[]]$Headers,
        [Parameter(Mandatory)][string]$LiteralPath
    )
    if ($Rows.Count -gt 0) {
        $Rows | Select-Object -Property $Headers | Export-Csv -LiteralPath $LiteralPath -NoTypeInformation -Encoding UTF8
        return
    }
    $template = [ordered]@{}
    foreach ($header in $Headers) { $template[$header] = '' }
    $headerLine = ([pscustomobject]$template | ConvertTo-Csv -NoTypeInformation)[0]
    Set-Content -LiteralPath $LiteralPath -Value $headerLine -Encoding UTF8
}

$requiredCommands = @('Get-MgContext','Invoke-MgGraphRequest')
$missingCommands = @($requiredCommands | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
if ($missingCommands.Count -gt 0) { throw "Missing Microsoft Graph command(s): $($missingCommands -join ', ')." }
$context = Get-MgContext
if ($null -eq $context) { throw 'No active Microsoft Graph session was found.' }

if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath -Force }
$resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
$targetId = ConvertTo-NormalizedId $TargetAppId
$warnings = [System.Collections.Generic.List[object]]::new()

$builtInRiskCatalog = [ordered]@{
    'AppRoleAssignment.ReadWrite.All'               = @{ Severity='Critical'; Category='Privilege escalation'; Reason='Can grant application permissions to service principals.' }
    'DelegatedPermissionGrant.ReadWrite.All'         = @{ Severity='Critical'; Category='Consent management'; Reason='Can create or modify delegated permission grants.' }
    'RoleManagement.ReadWrite.Directory'             = @{ Severity='Critical'; Category='Directory roles'; Reason='Can modify Entra role assignments and role configuration.' }
    'PrivilegedAccess.ReadWrite.AzureAD'             = @{ Severity='Critical'; Category='Privileged access'; Reason='Can modify privileged access for Entra roles.' }
    'PrivilegedAccess.ReadWrite.AzureADGroup'        = @{ Severity='Critical'; Category='Privileged access'; Reason='Can modify privileged access for groups.' }
    'PrivilegedAccess.ReadWrite.AzureResources'      = @{ Severity='Critical'; Category='Privileged access'; Reason='Can modify privileged access for Azure resources.' }
    'Policy.ReadWrite.ConditionalAccess'             = @{ Severity='Critical'; Category='Security policy'; Reason='Can modify Conditional Access policies.' }
    'UserAuthenticationMethod.ReadWrite.All'         = @{ Severity='Critical'; Category='Authentication methods'; Reason='Can modify authentication methods for users.' }
    'Directory.ReadWrite.All'                        = @{ Severity='Critical'; Category='Directory modification'; Reason='Can broadly modify directory data.' }
    'Organization.ReadWrite.All'                     = @{ Severity='High'; Category='Organization'; Reason='Can modify organization information.' }
    'User.ReadWrite.All'                             = @{ Severity='High'; Category='Identity modification'; Reason='Can broadly modify user objects.' }
    'Group.ReadWrite.All'                            = @{ Severity='High'; Category='Group control'; Reason='Can modify groups and memberships.' }
    'GroupMember.ReadWrite.All'                      = @{ Severity='High'; Category='Group control'; Reason='Can modify group membership across the directory.' }
    'Mail.ReadWrite'                                 = @{ Severity='High'; Category='Mail'; Reason='Can read and modify mailbox content.' }
    'Mail.Send'                                      = @{ Severity='High'; Category='Mail'; Reason='Can send mail as the signed-in user.' }
    'Calendars.ReadWrite'                            = @{ Severity='High'; Category='Calendar'; Reason='Can read and modify calendars.' }
    'Contacts.ReadWrite'                             = @{ Severity='High'; Category='Contacts'; Reason='Can read and modify contacts.' }
    'Files.ReadWrite.All'                            = @{ Severity='High'; Category='Files'; Reason='Can broadly read and modify files.' }
    'Sites.FullControl.All'                          = @{ Severity='Critical'; Category='SharePoint'; Reason='Can exercise full control over SharePoint sites.' }
    'DeviceManagementManagedDevices.PrivilegedOperations.All' = @{ Severity='Critical'; Category='Device management'; Reason='Can perform privileged operations on managed devices.' }
    'DeviceManagementManagedDevices.ReadWrite.All'  = @{ Severity='High'; Category='Device management'; Reason='Can read and modify managed devices.' }
    'DeviceManagementConfiguration.ReadWrite.All'   = @{ Severity='High'; Category='Device management'; Reason='Can modify device-management configuration.' }
    'Tasks.ReadWrite'                                = @{ Severity='Medium'; Category='Tasks'; Reason='Can create, read, update, and delete user tasks.' }
    'Tasks.ReadWrite.Shared'                         = @{ Severity='Medium'; Category='Tasks'; Reason='Can modify user and shared tasks.' }
}

$riskCatalog = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$customCatalog = $PSBoundParameters.ContainsKey('HighRiskScopes') -and @($HighRiskScopes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
if ($customCatalog) {
    foreach ($scope in @($HighRiskScopes | Where-Object { $_ } | Sort-Object -Unique)) {
        $riskCatalog[$scope.Trim()] = [pscustomobject]@{ Severity='High'; Category='Custom'; Reason='Matches a caller-supplied high-risk scope.' }
    }
} else {
    foreach ($scope in $builtInRiskCatalog.Keys) { $riskCatalog[$scope] = [pscustomobject]$builtInRiskCatalog[$scope] }
}
if ($riskCatalog.Count -eq 0) { throw 'The active delegated-scope risk catalog is empty.' }

Write-Host "Reusing Microsoft Graph session for $($context.Account). No new consent request will be made." -ForegroundColor Cyan
Write-Host "Tenant ID: $($context.TenantId) | Authentication: $($context.AuthType)" -ForegroundColor DarkGray
Write-Host "Active delegated-risk catalog scopes: $($riskCatalog.Count) ($(if($customCatalog){'custom'}else{'built-in'}))" -ForegroundColor DarkGray

$filter = [uri]::EscapeDataString("appId eq '$targetId'")
$appResults = @(Get-GraphCollection "https://graph.microsoft.com/v1.0/applications?`$filter=$filter&`$select=id,appId,displayName&`$top=2")
$spResults = @(Get-GraphCollection "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter&`$select=id,appId,displayName,accountEnabled,appRoleAssignmentRequired,appRoles&`$top=2")
if ($spResults.Count -eq 0) { throw "No service principal was found for AppId $targetId." }
if ($spResults.Count -gt 1) { throw "Multiple service principals were returned for AppId $targetId." }
$app = if ($appResults.Count -eq 1) { $appResults[0] } else { $null }
$sp = $spResults[0]
$spId = ConvertTo-NormalizedId (Get-OptionalProperty $sp 'id')
$displayName = [string](Get-OptionalProperty $sp 'displayName' $targetId)
$prefix = Join-Path $resolvedOutputPath "delegation-risk-audit-$(ConvertTo-SafeFileName $displayName)-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

$resourceCache = @{}
$principalCache = @{}
$grantRows = @()
$riskRows = @()
$rawGrants = @(Invoke-OptionalGraphCollection "https://graph.microsoft.com/v1.0/servicePrincipals/${spId}/oauth2PermissionGrants?`$select=id,clientId,consentType,principalId,resourceId,scope&`$top=999" 'Delegated OAuth grants' $warnings)
foreach ($grant in $rawGrants) {
    $resourceId = ConvertTo-NormalizedId (Get-OptionalProperty $grant 'resourceId')
    if (-not $resourceCache.ContainsKey($resourceId)) {
        try {
            $resourceCache[$resourceId] = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/${resourceId}?`$select=id,appId,displayName,oauth2PermissionScopes" -OutputType PSObject
        } catch {
            $resourceCache[$resourceId] = [pscustomobject]@{ id=$resourceId; appId=''; displayName=''; oauth2PermissionScopes=@() }
            $warnings.Add([pscustomobject]@{ DataSet='Resource service principal'; Message="Could not resolve resource ${resourceId}: $($_.Exception.Message)" })
        }
    }
    $resource = $resourceCache[$resourceId]
    $principalId = ConvertTo-NormalizedId (Get-OptionalProperty $grant 'principalId')
    $principal = $null
    if ($principalId) {
        if (-not $principalCache.ContainsKey($principalId)) {
            try { $principalCache[$principalId] = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$principalId" -OutputType PSObject }
            catch { $principalCache[$principalId] = [pscustomobject]@{ id=$principalId; displayName=''; userPrincipalName=''; '@odata.type'='' } }
        }
        $principal = $principalCache[$principalId]
    }
    $definitions = @(Get-OptionalProperty $resource 'oauth2PermissionScopes' @())
    foreach ($scope in @(@(([string](Get-OptionalProperty $grant 'scope')) -split '\s+') | Where-Object { $_ } | Sort-Object -Unique)) {
        $definition = @($definitions | Where-Object { [string](Get-OptionalProperty $_ 'value') -eq $scope }) | Select-Object -First 1
        $isRisk = $riskCatalog.ContainsKey($scope)
        $risk = if ($isRisk) { $riskCatalog[$scope] } else { $null }
        $row = [pscustomobject][ordered]@{
            Severity = if($isRisk){$risk.Severity}else{'Informational'}
            Category = if($isRisk){$risk.Category}else{'NotCataloged'}
            RiskCatalogMatch = $isRisk
            Permission = $scope
            PermissionDisplayName = Get-OptionalProperty $definition 'adminConsentDisplayName'
            ConsentType = Get-OptionalProperty $grant 'consentType'
            TenantWideConsent = ([string](Get-OptionalProperty $grant 'consentType')) -eq 'AllPrincipals'
            ConsentPrincipalId = $principalId
            ConsentPrincipalName = Get-OptionalProperty $principal 'displayName'
            ConsentPrincipalUserPrincipalName = Get-OptionalProperty $principal 'userPrincipalName'
            ResourceDisplayName = Get-OptionalProperty $resource 'displayName'
            ResourceAppId = Get-OptionalProperty $resource 'appId'
            ResourceObjectId = $resourceId
            GrantId = Get-OptionalProperty $grant 'id'
            RiskReason = if($isRisk){$risk.Reason}else{'Scope is not in the active delegated-risk catalog.'}
        }
        $grantRows += $row
        if ($isRisk) { $riskRows += $row }
    }
}

$ownerRows = @()
if ($null -ne $app) {
    $appId = ConvertTo-NormalizedId (Get-OptionalProperty $app 'id')
    foreach ($owner in @(Invoke-OptionalGraphCollection "https://graph.microsoft.com/v1.0/applications/${appId}/owners?`$select=id,displayName,userPrincipalName,mail,appId&`$top=999" 'Application owners' $warnings)) {
        $ownerRows += [pscustomobject][ordered]@{
            OwnerSource='ApplicationRegistration'; ObjectId=Get-OptionalProperty $owner 'id'; ObjectType=([string](Get-OptionalProperty $owner '@odata.type')).Replace('#microsoft.graph.','')
            DisplayName=Get-OptionalProperty $owner 'displayName'; UserPrincipalName=Get-OptionalProperty $owner 'userPrincipalName'; Mail=Get-OptionalProperty $owner 'mail'; ApplicationId=Get-OptionalProperty $owner 'appId'
        }
    }
}
foreach ($owner in @(Invoke-OptionalGraphCollection "https://graph.microsoft.com/v1.0/servicePrincipals/${spId}/owners?`$select=id,displayName,userPrincipalName,mail,appId&`$top=999" 'Service principal owners' $warnings)) {
    $ownerRows += [pscustomobject][ordered]@{
        OwnerSource='ServicePrincipal'; ObjectId=Get-OptionalProperty $owner 'id'; ObjectType=([string](Get-OptionalProperty $owner '@odata.type')).Replace('#microsoft.graph.','')
        DisplayName=Get-OptionalProperty $owner 'displayName'; UserPrincipalName=Get-OptionalProperty $owner 'userPrincipalName'; Mail=Get-OptionalProperty $owner 'mail'; ApplicationId=Get-OptionalProperty $owner 'appId'
    }
}
$ownerRows = @($ownerRows | Sort-Object OwnerSource,ObjectId -Unique)

$assignmentRows = @()
$targetRoles = @(Get-OptionalProperty $sp 'appRoles' @())
# appRoleAssignedTo is the correct relationship for users/groups/service principals assigned to this enterprise application.
foreach ($assignment in @(Invoke-OptionalGraphCollection "https://graph.microsoft.com/v1.0/servicePrincipals/${spId}/appRoleAssignedTo?`$select=id,appRoleId,principalId,principalDisplayName,principalType,createdDateTime&`$top=999" 'Enterprise application assignments' $warnings)) {
    $roleId = ConvertTo-NormalizedId (Get-OptionalProperty $assignment 'appRoleId')
    $role = @($targetRoles | Where-Object { (ConvertTo-NormalizedId (Get-OptionalProperty $_ 'id')) -eq $roleId }) | Select-Object -First 1
    $assignmentRows += [pscustomobject][ordered]@{
        PrincipalId=Get-OptionalProperty $assignment 'principalId'; PrincipalType=Get-OptionalProperty $assignment 'principalType'; PrincipalDisplayName=Get-OptionalProperty $assignment 'principalDisplayName'
        AppRole=Get-OptionalProperty $role 'value' $(if($roleId -eq '00000000-0000-0000-0000-000000000000'){'Default access'}else{"Unresolved:$roleId"})
        AppRoleDisplayName=Get-OptionalProperty $role 'displayName'; AssignmentId=Get-OptionalProperty $assignment 'id'; CreatedDateTimeUtc=ConvertTo-UtcText (Get-OptionalProperty $assignment 'createdDateTime')
    }
}

$summary = [pscustomobject][ordered]@{
    AuditGeneratedUtc=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); TenantId=[string]$context.TenantId; ApplicationClientId=$targetId; DisplayName=$displayName
    ServicePrincipalObjectId=$spId; AccountEnabled=Get-OptionalProperty $sp 'accountEnabled'; AppRoleAssignmentRequired=Get-OptionalProperty $sp 'appRoleAssignmentRequired'
    RawDelegatedGrantCount=$rawGrants.Count; DelegatedScopeCount=$grantRows.Count; TenantWideScopeCount=@($grantRows|Where-Object TenantWideConsent).Count
    RiskCatalogCount=$riskCatalog.Count; RiskFindingCount=$riskRows.Count; CriticalFindingCount=@($riskRows|Where-Object Severity -eq 'Critical').Count
    HighFindingCount=@($riskRows|Where-Object Severity -eq 'High').Count; MediumFindingCount=@($riskRows|Where-Object Severity -eq 'Medium').Count
    OwnerCount=$ownerRows.Count; EnterpriseAssignmentCount=$assignmentRows.Count; WarningCount=$warnings.Count
}
$profile=[pscustomobject][ordered]@{Summary=$summary;DelegatedScopes=@($grantRows);RiskFindings=@($riskRows);Owners=@($ownerRows);EnterpriseAssignments=@($assignmentRows);RawGrants=@($rawGrants);Warnings=@($warnings)}

$paths=[ordered]@{Json="$prefix.json";Summary="$prefix-summary.csv";Scopes="$prefix-delegated-scopes.csv";Risks="$prefix-risk-findings.csv";Owners="$prefix-owners.csv";Assignments="$prefix-enterprise-assignments.csv";Raw="$prefix-raw-grants.csv";Warnings="$prefix-warnings.csv"}
$profile|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $paths.Json -Encoding UTF8
$summary|Export-Csv -LiteralPath $paths.Summary -NoTypeInformation -Encoding UTF8
Export-CsvWithHeaders $grantRows @('Severity','Category','RiskCatalogMatch','Permission','PermissionDisplayName','ConsentType','TenantWideConsent','ConsentPrincipalId','ConsentPrincipalName','ConsentPrincipalUserPrincipalName','ResourceDisplayName','ResourceAppId','ResourceObjectId','GrantId','RiskReason') $paths.Scopes
Export-CsvWithHeaders $riskRows @('Severity','Category','Permission','PermissionDisplayName','ConsentType','TenantWideConsent','ConsentPrincipalId','ConsentPrincipalName','ConsentPrincipalUserPrincipalName','ResourceDisplayName','ResourceAppId','ResourceObjectId','GrantId','RiskReason') $paths.Risks
Export-CsvWithHeaders $ownerRows @('OwnerSource','ObjectId','ObjectType','DisplayName','UserPrincipalName','Mail','ApplicationId') $paths.Owners
Export-CsvWithHeaders $assignmentRows @('PrincipalId','PrincipalType','PrincipalDisplayName','AppRole','AppRoleDisplayName','AssignmentId','CreatedDateTimeUtc') $paths.Assignments
Export-CsvWithHeaders $rawGrants @('id','clientId','consentType','principalId','resourceId','scope') $paths.Raw
Export-CsvWithHeaders @($warnings) @('DataSet','Message') $paths.Warnings

Write-Host ''
Write-Host 'Delegated permission risk audit complete.' -ForegroundColor Green
Write-Host "Display name                        : $displayName"
Write-Host "User assignment required            : $($summary.AppRoleAssignmentRequired)"
Write-Host "Raw delegated grants                : $($summary.RawDelegatedGrantCount)"
Write-Host "Delegated permission scopes         : $($summary.DelegatedScopeCount)"
Write-Host "  Tenant-wide scopes                : $($summary.TenantWideScopeCount)"
Write-Host "Risk catalog matches                : $($summary.RiskFindingCount)"
Write-Host "  Critical                          : $($summary.CriticalFindingCount)"
Write-Host "  High                              : $($summary.HighFindingCount)"
Write-Host "  Medium                            : $($summary.MediumFindingCount)"
Write-Host "Owners                              : $($summary.OwnerCount)"
Write-Host "Enterprise application assignments  : $($summary.EnterpriseAssignmentCount)"
Write-Host "Warnings                            : $($summary.WarningCount)"
Write-Host "Risk findings CSV                   : $($paths.Risks)"
Write-Host "All delegated scopes CSV            : $($paths.Scopes)"
Write-Host "Owners CSV                          : $($paths.Owners)"
Write-Host "Assignments CSV                     : $($paths.Assignments)"
Write-Host "Governance JSON                     : $($paths.Json)"
Write-Host ''
Write-Host 'A catalog match indicates a granted capability requiring validation; it does not prove misuse or compromise.' -ForegroundColor Yellow
