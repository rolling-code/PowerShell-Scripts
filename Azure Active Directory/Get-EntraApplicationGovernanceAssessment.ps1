#requires -Version 7.2
<#
.SYNOPSIS
    Performs a read-only Microsoft Entra application governance assessment and exports a multi-sheet Excel workbook.
.DESCRIPTION
    Collects application registrations, service principals, owners, active directory-role assignments,
    Microsoft Graph application permissions, delegated grants, credentials, App Instance Property Lock,
    publisher verification, multitenant posture, user-assignment settings, sign-in activity when available,
    and evidence-based governance classifications.

    The script is designed for public reuse. It contains no tenant-specific identifiers and performs no changes.
.VERSION
    1.2.0
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PWD ('EntraApplicationGovernance-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [ValidateSet('AzureCLI','GraphInteractive','ExistingGraph')]
    [string]$AuthenticationMode = 'AzureCLI',
    [string]$TenantId,
    [switch]$SkipSignInActivity,
    [switch]$DoNotInstallMissingModules,
    [ValidateRange(1,3650)]
    [int]$OldAppAgeDays = 365,
    [int]$GraphPageSize = 999
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ScriptVersion = '1.2.0'
$GraphRoot = 'https://graph.microsoft.com/v1.0'
$GraphBetaRoot = 'https://graph.microsoft.com/beta'
$StartedUtc = [datetime]::UtcNow
$Errors = [System.Collections.Generic.List[object]]::new()

function Write-Stage {
    param([string]$Message)
    Write-Host ('[{0}] [STEP] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Cyan
}
function Write-Status {
    param([string]$Message)
    Write-Host ('[{0}] [INFO] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Gray
}
function Write-Pass {
    param([string]$Message)
    Write-Host ('[{0}] [PASS] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Green
}
function Write-WarnMessage {
    param([string]$Message)
    Write-Host ('[{0}] [WARN] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Yellow
}
function Add-AssessmentError {
    param([string]$Stage, [string]$ObjectType, [string]$ObjectId, [string]$ObjectName, [string]$Message)
    $Errors.Add([pscustomobject]@{
        TimestampUtc = [datetime]::UtcNow.ToString('o')
        Stage = $Stage
        ObjectType = $ObjectType
        ObjectId = $ObjectId
        ObjectName = $ObjectName
        Message = $Message
    })
}
function Ensure-Module {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        if ($DoNotInstallMissingModules) {
            throw "Required module '$Name' is not installed."
        }
        Write-WarnMessage "Installing missing module '$Name' for the current user."
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $Name -ErrorAction Stop
}
function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri, [string]$Stage = 'Graph collection')
    $Items = [System.Collections.Generic.List[object]]::new()
    $Next = $Uri
    $Page = 0
    while (-not [string]::IsNullOrWhiteSpace($Next)) {
        $Page++
        Write-Status "$Stage - page $Page"
        $Response = Invoke-MgGraphRequest -Method GET -Uri $Next -OutputType PSObject
        $ValueProperty = $Response.PSObject.Properties['value']
        if ($null -ne $ValueProperty -and $null -ne $ValueProperty.Value) {
            foreach ($Item in @($ValueProperty.Value)) { $Items.Add($Item) }
        }
        $NextProperty = $Response.PSObject.Properties['@odata.nextLink']
        $Next = if ($null -ne $NextProperty -and -not [string]::IsNullOrWhiteSpace([string]$NextProperty.Value)) {
            [string]$NextProperty.Value
        } else { $null }
    }
    return $Items.ToArray()
}
function Get-GraphCollectionSafe {
    param([Parameter(Mandatory)][string]$Uri, [string]$Stage, [string]$ObjectType, [string]$ObjectId, [string]$ObjectName)
    try { return @(Get-GraphCollection -Uri $Uri -Stage $Stage) }
    catch {
        Add-AssessmentError -Stage $Stage -ObjectType $ObjectType -ObjectId $ObjectId -ObjectName $ObjectName -Message $_.Exception.Message
        return @()
    }
}
function Join-Values {
    param($Values)
    if ($null -eq $Values) { return '' }
    return (@($Values) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique) -join '; '
}
function Get-PropertyValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $null }
    return $Property.Value
}

function Get-PropertyValues {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$PropertyName
    )

    $Values = [System.Collections.Generic.List[object]]::new()
    foreach ($Item in @($InputObject)) {
        if ($null -eq $Item) { continue }
        $Property = $Item.PSObject.Properties[$PropertyName]
        if ($null -ne $Property -and $null -ne $Property.Value) {
            $Values.Add($Property.Value)
        }
    }
    return $Values.ToArray()
}

function Test-HighImpactPermission {
    param([string]$Permission)
    $Patterns = @(
        '^Application\.ReadWrite\.', '^AppRoleAssignment\.ReadWrite\.', '^RoleManagement\.',
        '^Directory\.ReadWrite\.', '^User\.ReadWrite\.All$', '^Group\.ReadWrite\.All$',
        '^Mail\.(ReadWrite|Send)$', '^Sites\.(FullControl|ReadWrite)\.All$',
        '^Files\.ReadWrite\.All$', '^DeviceManagement.*ReadWrite', '^Policy\.ReadWrite\.',
        '^DelegatedPermissionGrant\.ReadWrite\.', '^EntitlementManagement\.ReadWrite\.'
    )
    foreach ($Pattern in $Patterns) { if ($Permission -match $Pattern) { return $true } }
    return $false
}
function Get-CredentialRows {
    param($Application, [string]$Type, $Credentials)
    $Rows = [System.Collections.Generic.List[object]]::new()
    foreach ($Credential in @($Credentials)) {
        $EndDate = Get-PropertyValue $Credential 'endDateTime'
        $StartDate = Get-PropertyValue $Credential 'startDateTime'
        $DaysToExpiry = $null
        $State = 'Unknown'
        if ($EndDate) {
            $End = [datetime]$EndDate
            $DaysToExpiry = [math]::Floor(($End.ToUniversalTime() - [datetime]::UtcNow).TotalDays)
            $State = if ($DaysToExpiry -lt 0) { 'Expired' } elseif ($DaysToExpiry -le 30) { 'ExpiresWithin30Days' } elseif ($DaysToExpiry -le 90) { 'ExpiresWithin90Days' } else { 'ValidBeyond90Days' }
        }
        $Rows.Add([pscustomobject]@{
            ApplicationDisplayName = $Application.displayName
            AppId = $Application.appId
            ApplicationObjectId = $Application.id
            CredentialType = $Type
            KeyId = Get-PropertyValue $Credential 'keyId'
            DisplayName = Get-PropertyValue $Credential 'displayName'
            StartDateTime = $StartDate
            EndDateTime = $EndDate
            DaysToExpiry = $DaysToExpiry
            State = $State
            Hint = Get-PropertyValue $Credential 'hint'
            Usage = Get-PropertyValue $Credential 'usage'
            KeyType = Get-PropertyValue $Credential 'type'
        })
    }
    return $Rows.ToArray()
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ' Microsoft Entra Application Governance Assessment' -ForegroundColor White
Write-Host " Version: $ScriptVersion" -ForegroundColor White
Write-Host ' Mode: READ-ONLY' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ''

Ensure-Module -Name 'Microsoft.Graph.Authentication'
Ensure-Module -Name 'ImportExcel'

$Scopes = @(
    'Application.Read.All',
    'Directory.Read.All',
    'RoleManagement.Read.Directory',
    'DelegatedPermissionGrant.Read.All',
    'AuditLog.Read.All'
)

$AssessmentIdentity = $null
$AssessmentTenantId = $null
$AuthenticationClient = $null
$GrantedAuthorization = @()
$TokenResponse = $null
$GraphAccessToken = $null
$SecureGraphAccessToken = $null
$Claims = $null

Write-Stage "Preparing Microsoft Graph authentication mode: $AuthenticationMode"

switch ($AuthenticationMode) {
    'AzureCLI' {
        if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
            throw 'Azure CLI was not found. Install Azure CLI or use -AuthenticationMode GraphInteractive.'
        }

        $AzAccountJson = az account show --output json 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Azure CLI is not authenticated. Run az login first. Details: $AzAccountJson"
        }
        $AzAccount = $AzAccountJson | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            $TenantId = [string]$AzAccount.tenantId
        }

        Write-Status "Azure subscription context: $($AzAccount.name)"
        Write-Status "Azure subscription ID: $($AzAccount.id)"
        Write-Status "Requesting a Microsoft Graph token for tenant $TenantId through the existing Azure CLI session."

        $TokenJson = az account get-access-token --tenant $TenantId --resource 'https://graph.microsoft.com/' --output json 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Azure CLI did not return a Microsoft Graph token. Details: $TokenJson"
        }
        $TokenResponse = $TokenJson | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace([string]$TokenResponse.accessToken)) {
            throw 'Azure CLI returned no Microsoft Graph access token.'
        }
        $GraphAccessToken = [string]$TokenResponse.accessToken

        $JwtParts = $GraphAccessToken.Split('.')
        if ($JwtParts.Count -lt 2) { throw 'The returned Microsoft Graph token is not a valid JWT.' }
        $JwtPayload = $JwtParts[1].Replace('-', '+').Replace('_', '/')
        switch ($JwtPayload.Length % 4) {
            2 { $JwtPayload += '==' }
            3 { $JwtPayload += '=' }
        }
        $DecodedPayload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($JwtPayload))
        $Claims = $DecodedPayload | ConvertFrom-Json

        $ExpectedAudiences = @('https://graph.microsoft.com', 'https://graph.microsoft.com/', '00000003-0000-0000-c000-000000000000')
        if ([string]$Claims.aud -notin $ExpectedAudiences) {
            throw "The Azure CLI token audience '$($Claims.aud)' is not Microsoft Graph."
        }
        if ([string]$Claims.tid -ne $TenantId) {
            throw "The token tenant '$($Claims.tid)' does not match requested tenant '$TenantId'."
        }

        $AssessmentIdentity = if ($Claims.upn) { [string]$Claims.upn } elseif ($Claims.preferred_username) { [string]$Claims.preferred_username } else { [string]$AzAccount.user.name }
        $AssessmentTenantId = [string]$Claims.tid
        $AuthenticationClient = if ($Claims.app_displayname) { [string]$Claims.app_displayname } else { "Azure CLI ($($Claims.appid))" }
        if ($Claims.scp) { $GrantedAuthorization = @(([string]$Claims.scp) -split ' ') }
        elseif ($Claims.roles) { $GrantedAuthorization = @($Claims.roles) }

        $SecureGraphAccessToken = ConvertTo-SecureString -String $GraphAccessToken -AsPlainText -Force
        Connect-MgGraph -AccessToken $SecureGraphAccessToken -NoWelcome
    }
    'GraphInteractive' {
        Write-WarnMessage 'Interactive mode may display an approval-required dialog if the Microsoft Graph PowerShell client lacks administrator consent.'
        $ConnectParameters = @{ Scopes = $Scopes; NoWelcome = $true }
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $ConnectParameters.TenantId = $TenantId }
        Connect-MgGraph @ConnectParameters
        $Context = Get-MgContext
        if ($null -eq $Context) { throw 'Microsoft Graph context was not established.' }
        $AssessmentIdentity = [string]$Context.Account
        $AssessmentTenantId = [string]$Context.TenantId
        $AuthenticationClient = 'Microsoft Graph Command Line Tools'
        $GrantedAuthorization = @($Context.Scopes)
    }
    'ExistingGraph' {
        $Context = Get-MgContext
        if ($null -eq $Context -or [string]::IsNullOrWhiteSpace([string]$Context.TenantId)) {
            throw 'No existing Microsoft Graph context was found. Connect first or use -AuthenticationMode AzureCLI.'
        }
        $AssessmentIdentity = [string]$Context.Account
        $AssessmentTenantId = [string]$Context.TenantId
        $AuthenticationClient = 'Existing Microsoft Graph context'
        $GrantedAuthorization = @($Context.Scopes)
    }
}

if ([string]::IsNullOrWhiteSpace($AssessmentTenantId)) { throw 'The Microsoft Graph tenant could not be determined.' }
Write-Pass "Identity: $AssessmentIdentity"
Write-Pass "Tenant ID: $AssessmentTenantId"
Write-Pass "Authentication client: $AuthenticationClient"
Write-Status ('Token authorization: ' + (Join-Values $GrantedAuthorization))
Write-Status 'The Azure subscription does not scope Microsoft Graph directory data; tenant and token authorization determine collection coverage.'
Write-Status 'No application, service principal, owner, credential, consent, role, or policy objects will be modified.'

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$WorkbookPath = Join-Path $OutputDirectory ('Entra-Application-Governance-{0}.xlsx' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$JsonPath = [System.IO.Path]::ChangeExtension($WorkbookPath, '.json')

Write-Stage 'Collecting tenant applications.'
$ApplicationUri = "$GraphRoot/applications?`$top=$GraphPageSize&`$select=id,appId,displayName,createdDateTime,signInAudience,publisherDomain,verifiedPublisher,passwordCredentials,keyCredentials,servicePrincipalLockConfiguration,requiredResourceAccess,notes,tags,disabledByMicrosoftStatus,identifierUris,web,spa,publicClient"
$Applications = @(Get-GraphCollection -Uri $ApplicationUri -Stage 'Applications')
Write-Pass "Applications collected: $($Applications.Count)"

Write-Stage 'Collecting tenant service principals.'
$ServicePrincipalUri = "$GraphBetaRoot/servicePrincipals?`$top=$GraphPageSize&`$select=id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,appRoleAssignmentRequired,verifiedPublisher,preferredSingleSignOnMode,notificationEmailAddresses,tags,createdDateTime,signInActivity,signInAudience,publisherName,homepage,replyUrls,servicePrincipalNames,disabledByMicrosoftStatus,passwordCredentials,keyCredentials,appRoles,oauth2PermissionScopes"
$ServicePrincipals = @(Get-GraphCollection -Uri $ServicePrincipalUri -Stage 'Service principals')
Write-Pass "Service principals collected: $($ServicePrincipals.Count)"

$ApplicationByAppId = @{}
foreach ($InventoryApplication in $Applications) {
    if (-not [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $InventoryApplication 'appId'))) {
        $ApplicationByAppId[[string](Get-PropertyValue $InventoryApplication 'appId')] = $InventoryApplication
    }
}

$ServicePrincipalByAppId = @{}
$ServicePrincipalById = @{}
$AppRoleNameByResourceId = @{}
foreach ($Sp in $ServicePrincipals) {
    if ($Sp.appId -and -not $ServicePrincipalByAppId.ContainsKey([string]$Sp.appId)) { $ServicePrincipalByAppId[[string]$Sp.appId] = $Sp }
    $ServicePrincipalById[[string]$Sp.id] = $Sp
    $RoleMap = @{}
    foreach ($Role in @($Sp.appRoles)) { if ($Role.id -and $Role.value) { $RoleMap[[string]$Role.id] = [string]$Role.value } }
    $AppRoleNameByResourceId[[string]$Sp.id] = $RoleMap
}

Write-Stage 'Collecting active Microsoft Entra directory-role assignments and definitions.'
# The unified RBAC roleDefinitions endpoint supports $filter and $expand, but not $top or $select.
# Use the documented collection URI without unsupported query options.
$RoleDefinitions = @(Get-GraphCollectionSafe `
    -Uri "$GraphRoot/roleManagement/directory/roleDefinitions" `
    -Stage 'Role definitions' `
    -ObjectType 'Tenant' `
    -ObjectId $AssessmentTenantId `
    -ObjectName 'Microsoft Entra directory roles')

# Keep role-assignment collection independent. If the current token cannot read this endpoint,
# the assessment continues and records the limitation rather than terminating the entire run.
$RoleAssignments = @(Get-GraphCollectionSafe `
    -Uri "$GraphRoot/roleManagement/directory/roleAssignments" `
    -Stage 'Active role assignments' `
    -ObjectType 'Tenant' `
    -ObjectId $AssessmentTenantId `
    -ObjectName 'Microsoft Entra active role assignments')

if ($RoleDefinitions.Count -eq 0) {
    Write-WarnMessage 'No role definitions were returned. Owner-role correlation will be marked as a coverage limitation.'
} else {
    Write-Pass "Role definitions collected: $($RoleDefinitions.Count)"
}
if ($RoleAssignments.Count -eq 0) {
    Write-WarnMessage 'No active role assignments were returned. The script will not treat owners as confirmed non-admin solely from missing role data.'
} else {
    Write-Pass "Active role assignments collected: $($RoleAssignments.Count)"
}
$RoleCoverageAvailable = ($RoleDefinitions.Count -gt 0 -and $RoleAssignments.Count -gt 0)
$RoleDefinitionById = @{}
foreach ($Role in $RoleDefinitions) { $RoleDefinitionById[[string]$Role.id] = $Role }
$RolesByPrincipalId = @{}
foreach ($Assignment in $RoleAssignments) {
    $RolePrincipalId = [string]$Assignment.principalId
    if (-not $RolesByPrincipalId.ContainsKey($RolePrincipalId)) { $RolesByPrincipalId[$RolePrincipalId] = [System.Collections.Generic.List[string]]::new() }
    $RoleName = if ($RoleDefinitionById.ContainsKey([string]$Assignment.roleDefinitionId)) { [string]$RoleDefinitionById[[string]$Assignment.roleDefinitionId].displayName } else { [string]$Assignment.roleDefinitionId }
    $RolesByPrincipalId[$RolePrincipalId].Add($RoleName)
}
Write-Stage 'Resolving Microsoft Graph application-role definitions.'
$GraphSp = $ServicePrincipals | Where-Object { $_.appId -eq '00000003-0000-0000-c000-000000000000' } | Select-Object -First 1
if (-not $GraphSp) { throw 'Microsoft Graph service principal was not found in the tenant inventory.' }
$GraphSpDetail = Invoke-MgGraphRequest -Method GET -Uri "$GraphRoot/servicePrincipals/$($GraphSp.id)?`$select=id,appId,displayName,appRoles,oauth2PermissionScopes" -OutputType PSObject
$GraphAppRoleById = @{}
foreach ($Role in @($GraphSpDetail.appRoles)) { $GraphAppRoleById[[string]$Role.id] = [string]$Role.value }

$AppInventoryRows = [System.Collections.Generic.List[object]]::new()
$SpInventoryRows = [System.Collections.Generic.List[object]]::new()
$CombinedInventoryRows = [System.Collections.Generic.List[object]]::new()
$OldAppRows = [System.Collections.Generic.List[object]]::new()
$AllApplicationPermissionRows = [System.Collections.Generic.List[object]]::new()
$EnterpriseAssignmentRows = [System.Collections.Generic.List[object]]::new()
$StatusRows = [System.Collections.Generic.List[object]]::new()
$OwnerRows = [System.Collections.Generic.List[object]]::new()
$OwnerRoleRows = [System.Collections.Generic.List[object]]::new()
$GraphPermissionRows = [System.Collections.Generic.List[object]]::new()
$DelegatedGrantRows = [System.Collections.Generic.List[object]]::new()
$CredentialRows = [System.Collections.Generic.List[object]]::new()
$OwnerlessRows = [System.Collections.Generic.List[object]]::new()
$DisabledPrivilegedRows = [System.Collections.Generic.List[object]]::new()
$OwnershipMismatchRows = [System.Collections.Generic.List[object]]::new()
$LockRows = [System.Collections.Generic.List[object]]::new()
$PublisherRows = [System.Collections.Generic.List[object]]::new()
$MultitenantRows = [System.Collections.Generic.List[object]]::new()
$AssignmentRows = [System.Collections.Generic.List[object]]::new()
$SignInRows = [System.Collections.Generic.List[object]]::new()
$ClassificationRows = [System.Collections.Generic.List[object]]::new()
$RoleAssignmentRows = [System.Collections.Generic.List[object]]::new()

Write-Stage 'Building complete service-principal inventory.'
$SpInventoryIndex = 0
foreach ($InventorySp in $ServicePrincipals) {
    $SpInventoryIndex++
    if (($SpInventoryIndex % 250) -eq 0 -or $SpInventoryIndex -eq $ServicePrincipals.Count) {
        Write-Status "Service-principal inventory: $SpInventoryIndex of $($ServicePrincipals.Count)"
    }

    $InventoryAppId = [string](Get-PropertyValue $InventorySp 'appId')
    $HomeApplication = if (-not [string]::IsNullOrWhiteSpace($InventoryAppId) -and $ApplicationByAppId.ContainsKey($InventoryAppId)) {
        $ApplicationByAppId[$InventoryAppId]
    } else {
        $null
    }
    $HomeRegistrationPresent = $null -ne $HomeApplication
    $ServicePrincipalType = [string](Get-PropertyValue $InventorySp 'servicePrincipalType')
    $OwnerOrganizationId = [string](Get-PropertyValue $InventorySp 'appOwnerOrganizationId')
    $PublisherName = [string](Get-PropertyValue $InventorySp 'publisherName')

    $OwnershipCategory = if ($HomeRegistrationPresent) {
        'Tenant-owned application'
    } elseif ($ServicePrincipalType -eq 'ManagedIdentity') {
        'Managed identity'
    } elseif (-not [string]::IsNullOrWhiteSpace($OwnerOrganizationId) -and $OwnerOrganizationId -eq $AssessmentTenantId) {
        'Tenant-owned service principal without returned application registration'
    } elseif ($PublisherName -match '^Microsoft') {
        'Microsoft first-party or Microsoft-published application'
    } elseif ($ServicePrincipalType -eq 'Legacy') {
        'Legacy service principal'
    } elseif (-not [string]::IsNullOrWhiteSpace($OwnerOrganizationId)) {
        'External or multitenant enterprise application'
    } else {
        'Unknown or other'
    }

    $VerifiedPublisherObject = Get-PropertyValue $InventorySp 'verifiedPublisher'
    $SpInventoryRows.Add([pscustomobject]@{
        DisplayName                       = Get-PropertyValue $InventorySp 'displayName'
        ApplicationClientId               = $InventoryAppId
        ServicePrincipalObjectId          = Get-PropertyValue $InventorySp 'id'
        AccountEnabled                    = Get-PropertyValue $InventorySp 'accountEnabled'
        ServicePrincipalType              = $ServicePrincipalType
        CreatedDateTime                   = Get-PropertyValue $InventorySp 'createdDateTime'
        SignInAudience                    = Get-PropertyValue $InventorySp 'signInAudience'
        AppOwnerOrganizationId            = $OwnerOrganizationId
        PublisherName                     = $PublisherName
        VerifiedPublisher                 = if ($VerifiedPublisherObject) { Get-PropertyValue $VerifiedPublisherObject 'displayName' } else { '' }
        Homepage                          = Get-PropertyValue $InventorySp 'homepage'
        ReplyUrls                         = Join-Values (Get-PropertyValue $InventorySp 'replyUrls')
        ServicePrincipalNames             = Join-Values (Get-PropertyValue $InventorySp 'servicePrincipalNames')
        DisabledByMicrosoftStatus         = Get-PropertyValue $InventorySp 'disabledByMicrosoftStatus'
        PasswordCredentialCount           = @(Get-PropertyValue $InventorySp 'passwordCredentials').Count
        KeyCredentialCount                = @(Get-PropertyValue $InventorySp 'keyCredentials').Count
        AppRoleAssignmentRequired         = Get-PropertyValue $InventorySp 'appRoleAssignmentRequired'
        PreferredSingleSignOnMode         = Get-PropertyValue $InventorySp 'preferredSingleSignOnMode'
        Tags                              = Join-Values (Get-PropertyValue $InventorySp 'tags')
        HomeApplicationRegistrationPresent = $HomeRegistrationPresent
        HomeApplicationObjectId           = if ($HomeApplication) { Get-PropertyValue $HomeApplication 'id' } else { '' }
        OwnershipCategory                 = $OwnershipCategory
    })
}
Write-Pass "Complete service-principal inventory rows: $($SpInventoryRows.Count)"

$Index = 0
foreach ($Application in $Applications) {
    $Index++
    $Percent = [math]::Round(($Index / [math]::Max($Applications.Count, 1)) * 100, 1)
    Write-Host ('[{0}] [{1}/{2} - {3}%] Evaluating {4}' -f (Get-Date -Format 'HH:mm:ss'), $Index, $Applications.Count, $Percent, $Application.displayName) -ForegroundColor DarkCyan

    $Sp = if ($ServicePrincipalByAppId.ContainsKey([string]$Application.appId)) { $ServicePrincipalByAppId[[string]$Application.appId] } else { $null }

    # Force owner results to native arrays. PowerShell unwraps single-item output from
    # conditional expressions, which otherwise makes .Count unreliable under StrictMode.
    $Owners = @(
        Get-GraphCollectionSafe `
            -Uri "$GraphRoot/applications/$($Application.id)/owners?`$top=$GraphPageSize&`$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,onPremisesSyncEnabled,appId,servicePrincipalType" `
            -Stage 'Application owners' `
            -ObjectType 'Application' `
            -ObjectId $Application.id `
            -ObjectName $Application.displayName
    )

    $SpOwners = @()
    if ($null -ne $Sp) {
        $SpOwners = @(
            Get-GraphCollectionSafe `
                -Uri "$GraphRoot/servicePrincipals/$($Sp.id)/owners?`$top=$GraphPageSize&`$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,onPremisesSyncEnabled,appId,servicePrincipalType" `
                -Stage 'Service principal owners' `
                -ObjectType 'ServicePrincipal' `
                -ObjectId $Sp.id `
                -ObjectName $Sp.displayName
        )
    }

    $Created = if ($Application.createdDateTime) { [datetime]$Application.createdDateTime } else { $null }
    $AgeDays = if ($Created) { [math]::Floor(([datetime]::UtcNow - $Created.ToUniversalTime()).TotalDays) } else { $null }
    $AppInventoryRows.Add([pscustomobject]@{
        DisplayName = $Application.displayName
        ApplicationClientId = $Application.appId
        ApplicationObjectId = $Application.id
        CreatedDateTime = $Application.createdDateTime
        AgeDays = $AgeDays
        SignInAudience = $Application.signInAudience
        PublisherDomain = $Application.publisherDomain
        VerifiedPublisher = if ($Application.verifiedPublisher) { Get-PropertyValue $Application.verifiedPublisher 'displayName' } else { '' }
        DisabledByMicrosoftStatus = $Application.disabledByMicrosoftStatus
        PasswordCredentialCount = @($Application.passwordCredentials).Count
        KeyCredentialCount = @($Application.keyCredentials).Count
        IdentifierUris = Join-Values $Application.identifierUris
        Tags = Join-Values $Application.tags
    })
    if ($null -ne $AgeDays -and $AgeDays -ge $OldAppAgeDays) {
        $OldAppRows.Add([pscustomobject]@{
            DisplayName=$Application.displayName; ApplicationClientId=$Application.appId; ApplicationObjectId=$Application.id
            CreatedDateTime=$Application.createdDateTime; AgeDays=$AgeDays; ThresholdDays=$OldAppAgeDays
            ServicePrincipalEnabled=if($Sp){$Sp.accountEnabled}else{$null}; OwnerCount=$Owners.Count
            Disposition='Age is a review indicator only; validate ownership, activity, credentials, permissions, and business use.'
        })
    }

    $StatusRows.Add([pscustomobject]@{
        ApplicationDisplayName = $Application.displayName
        AppId = $Application.appId
        ApplicationObjectId = $Application.id
        ApplicationCreatedDateTime = $Application.createdDateTime
        ServicePrincipalObjectId = if ($Sp) { $Sp.id } else { '' }
        ServicePrincipalExists = [bool]$Sp
        ServicePrincipalEnabled = if ($Sp) { $Sp.accountEnabled } else { $null }
        ServicePrincipalType = if ($Sp) { $Sp.servicePrincipalType } else { '' }
        ServicePrincipalCreatedDateTime = if ($Sp) { $Sp.createdDateTime } else { $null }
        PreferredSingleSignOnMode = if ($Sp) { $Sp.preferredSingleSignOnMode } else { '' }
        ApplicationOwnerCount = $Owners.Count
        ServicePrincipalOwnerCount = $SpOwners.Count
    })

    foreach ($OwnerContext in @(@{ Type='Application'; Owners=$Owners }, @{ Type='ServicePrincipal'; Owners=$SpOwners })) {
        foreach ($Owner in @($OwnerContext.Owners)) {
            $OdataType = [string](Get-PropertyValue $Owner '@odata.type')
            $OwnerType = if ($OdataType) { $OdataType -replace '^#microsoft.graph\.', '' } elseif (Get-PropertyValue $Owner 'userPrincipalName') { 'user' } elseif (Get-PropertyValue $Owner 'appId') { 'servicePrincipal' } else { 'directoryObject' }
            $ActiveRoles = if ($RolesByPrincipalId.ContainsKey([string]$Owner.id)) { Join-Values $RolesByPrincipalId[[string]$Owner.id] } else { '' }
            $OwnerRows.Add([pscustomobject]@{
                ApplicationDisplayName = $Application.displayName
                AppId = $Application.appId
                OwnedObjectType = $OwnerContext.Type
                OwnerObjectId = $Owner.id
                OwnerType = $OwnerType
                OwnerDisplayName = $Owner.displayName
                OwnerUserPrincipalName = Get-PropertyValue $Owner 'userPrincipalName'
                OwnerAccountEnabled = Get-PropertyValue $Owner 'accountEnabled'
                OwnerUserType = Get-PropertyValue $Owner 'userType'
                OwnerOnPremisesSyncEnabled = Get-PropertyValue $Owner 'onPremisesSyncEnabled'
                OwnerAppId = Get-PropertyValue $Owner 'appId'
                DirectActiveEntraRoles = $ActiveRoles
            })
            $OwnerRoleRows.Add([pscustomobject]@{
                ApplicationDisplayName = $Application.displayName
                AppId = $Application.appId
                OwnerObjectId = $Owner.id
                OwnerDisplayName = $Owner.displayName
                OwnerUserPrincipalName = Get-PropertyValue $Owner 'userPrincipalName'
                OwnerAccountEnabled = Get-PropertyValue $Owner 'accountEnabled'
                HasDirectActiveEntraRole = if ($RoleCoverageAvailable) { -not [string]::IsNullOrWhiteSpace($ActiveRoles) } else { $null }
                DirectActiveEntraRoles = $ActiveRoles
                CoverageStatus = if ($RoleCoverageAvailable) { 'Available' } else { 'Unavailable' }
                CoverageNote = if ($RoleCoverageAvailable) { 'Direct active role assignments only; eligible PIM and transitive group-based roles require separate validation.' } else { 'Role-definition or role-assignment collection was unavailable. No owner role conclusion can be made.' }
            })
        }
    }

    foreach ($Row in @(Get-CredentialRows -Application $Application -Type 'Password' -Credentials $Application.passwordCredentials)) { $CredentialRows.Add($Row) }
    foreach ($Row in @(Get-CredentialRows -Application $Application -Type 'Certificate' -Credentials $Application.keyCredentials)) { $CredentialRows.Add($Row) }

    $Lock = Get-PropertyValue $Application 'servicePrincipalLockConfiguration'
    $LockRows.Add([pscustomobject]@{
        ApplicationDisplayName = $Application.displayName
        AppId = $Application.appId
        ApplicationObjectId = $Application.id
        SignInAudience = $Application.signInAudience
        CreatedDateTime = $Application.createdDateTime
        LockConfigured = $null -ne $Lock
        IsEnabled = if ($Lock) { Get-PropertyValue $Lock 'isEnabled' } else { $false }
        AllProperties = if ($Lock) { Get-PropertyValue $Lock 'allProperties' } else { $false }
        CredentialsWithUsageVerify = if ($Lock) { Get-PropertyValue $Lock 'credentialsWithUsageVerify' } else { $false }
        CredentialsWithUsageSign = if ($Lock) { Get-PropertyValue $Lock 'credentialsWithUsageSign' } else { $false }
        TokenEncryptionKeyId = if ($Lock) { Get-PropertyValue $Lock 'tokenEncryptionKeyId' } else { $false }
        ReviewDisposition = if ($Lock -and (Get-PropertyValue $Lock 'isEnabled')) { 'AlreadyProtected' } elseif ($Application.signInAudience -ne 'AzureADMyOrg') { 'ReviewForCompatibilityAndExternalInstances' } else { 'TargetedReviewOnly' }
    })

    $VerifiedPublisher = Get-PropertyValue $Application 'verifiedPublisher'
    $PublisherRows.Add([pscustomobject]@{
        ApplicationDisplayName = $Application.displayName
        AppId = $Application.appId
        PublisherDomain = $Application.publisherDomain
        VerifiedPublisherDisplayName = if ($VerifiedPublisher) { Get-PropertyValue $VerifiedPublisher 'displayName' } else { '' }
        VerifiedPublisherId = if ($VerifiedPublisher) { Get-PropertyValue $VerifiedPublisher 'verifiedPublisherId' } else { '' }
        AddedDateTime = if ($VerifiedPublisher) { Get-PropertyValue $VerifiedPublisher 'addedDateTime' } else { $null }
        IsPublisherVerified = [bool]($VerifiedPublisher -and (Get-PropertyValue $VerifiedPublisher 'verifiedPublisherId'))
    })

    $IsMultitenant = $Application.signInAudience -in @('AzureADMultipleOrgs','AzureADandPersonalMicrosoftAccount')
    $MultitenantRows.Add([pscustomobject]@{
        ApplicationDisplayName = $Application.displayName
        AppId = $Application.appId
        SignInAudience = $Application.signInAudience
        IsMultitenant = $IsMultitenant
        PublisherDomain = $Application.publisherDomain
        IsPublisherVerified = [bool]($VerifiedPublisher -and (Get-PropertyValue $VerifiedPublisher 'verifiedPublisherId'))
        AppInstancePropertyLockEnabled = [bool]($Lock -and (Get-PropertyValue $Lock 'isEnabled'))
        ReviewPriority = if ($IsMultitenant -and -not ($Lock -and (Get-PropertyValue $Lock 'isEnabled'))) { 'Review' } else { 'Routine' }
    })

    $AssignmentRows.Add([pscustomobject]@{
        ApplicationDisplayName = $Application.displayName
        AppId = $Application.appId
        ServicePrincipalObjectId = if ($Sp) { $Sp.id } else { '' }
        ServicePrincipalEnabled = if ($Sp) { $Sp.accountEnabled } else { $null }
        AppRoleAssignmentRequired = if ($Sp) { $Sp.appRoleAssignmentRequired } else { $null }
        Interpretation = if (-not $Sp) { 'No local service principal' } elseif ($Sp.appRoleAssignmentRequired) { 'User assignment required' } else { 'User assignment not required; access still depends on application and Conditional Access controls' }
    })

    if ($Sp) {
        $Assignments = @(Get-GraphCollectionSafe -Uri "$GraphRoot/servicePrincipals/$($Sp.id)/appRoleAssignments?`$top=$GraphPageSize" -Stage 'Application permissions' -ObjectType 'ServicePrincipal' -ObjectId $Sp.id -ObjectName $Sp.displayName)
        foreach ($Grant in $Assignments) {
            $ResourceId = [string]$Grant.resourceId
            $ResourceSp = if ($ServicePrincipalById.ContainsKey($ResourceId)) { $ServicePrincipalById[$ResourceId] } else { $null }
            $ResourceRoleMap = if ($AppRoleNameByResourceId.ContainsKey($ResourceId)) { $AppRoleNameByResourceId[$ResourceId] } else { @{} }
            $ResolvedPermission = if ($ResourceRoleMap.ContainsKey([string]$Grant.appRoleId)) { $ResourceRoleMap[[string]$Grant.appRoleId] } else { 'Unresolved:' + [string]$Grant.appRoleId }
            $AllApplicationPermissionRows.Add([pscustomobject]@{
                ApplicationDisplayName=$Application.displayName; AppId=$Application.appId; ServicePrincipalObjectId=$Sp.id
                ServicePrincipalEnabled=$Sp.accountEnabled; ResourceDisplayName=if($ResourceSp){$ResourceSp.displayName}else{$Grant.resourceDisplayName}
                ResourceAppId=if($ResourceSp){$ResourceSp.appId}else{''}; ResourceObjectId=$ResourceId
                Permission=$ResolvedPermission; PermissionType='Application'; HighImpact=Test-HighImpactPermission $ResolvedPermission
                AssignmentId=$Grant.id; CreatedDateTime=Get-PropertyValue $Grant 'createdDateTime'
            })
            if ($ResourceId -ne [string]$GraphSp.id) { continue }
            $Permission = if ($GraphAppRoleById.ContainsKey([string]$Grant.appRoleId)) { $GraphAppRoleById[[string]$Grant.appRoleId] } else { [string]$Grant.appRoleId }
            $GraphPermissionRows.Add([pscustomobject]@{
                ApplicationDisplayName = $Application.displayName
                AppId = $Application.appId
                ServicePrincipalObjectId = $Sp.id
                ServicePrincipalEnabled = $Sp.accountEnabled
                Permission = $Permission
                PermissionType = 'Application'
                HighImpact = Test-HighImpactPermission $Permission
                AssignmentId = $Grant.id
                CreatedDateTime = Get-PropertyValue $Grant 'createdDateTime'
            })
        }
        $OauthGrants = @(Get-GraphCollectionSafe -Uri "$GraphRoot/oauth2PermissionGrants?`$filter=clientId%20eq%20'$($Sp.id)'&`$top=$GraphPageSize" -Stage 'Delegated grants' -ObjectType 'ServicePrincipal' -ObjectId $Sp.id -ObjectName $Sp.displayName)
        foreach ($Grant in $OauthGrants) {
            $ResourceId = [string]$Grant.resourceId
            $ResourceSp = if ($ServicePrincipalById.ContainsKey($ResourceId)) { $ServicePrincipalById[$ResourceId] } else { $null }
            foreach ($Scope in @(([string]$Grant.scope -split '\s+') | Where-Object { $_ } | Sort-Object -Unique)) {
                $DelegatedGrantRows.Add([pscustomobject]@{
                    ApplicationDisplayName = $Application.displayName
                    AppId = $Application.appId
                    ServicePrincipalObjectId = $Sp.id
                    ConsentType = $Grant.consentType
                    PrincipalId = $Grant.principalId
                    ResourceDisplayName = if($ResourceSp){$ResourceSp.displayName}else{''}
                    ResourceAppId = if($ResourceSp){$ResourceSp.appId}else{''}
                    ResourceId = $ResourceId
                    Permission = $Scope
                    TenantWide = $Grant.consentType -eq 'AllPrincipals'
                    HighImpact = Test-HighImpactPermission $Scope
                    GrantId = $Grant.id
                })
            }
        }
        $EnterpriseAssignments = @(Get-GraphCollectionSafe -Uri "$GraphRoot/servicePrincipals/$($Sp.id)/appRoleAssignedTo?`$top=$GraphPageSize" -Stage 'Enterprise application assignments' -ObjectType 'ServicePrincipal' -ObjectId $Sp.id -ObjectName $Sp.displayName)
        foreach ($Assignment in $EnterpriseAssignments) {
            $TargetRoleMap = if ($AppRoleNameByResourceId.ContainsKey([string]$Sp.id)) { $AppRoleNameByResourceId[[string]$Sp.id] } else { @{} }
            $RoleName = if ([string]$Assignment.appRoleId -eq '00000000-0000-0000-0000-000000000000') { 'Default access' } elseif ($TargetRoleMap.ContainsKey([string]$Assignment.appRoleId)) { $TargetRoleMap[[string]$Assignment.appRoleId] } else { 'Unresolved:' + [string]$Assignment.appRoleId }
            $EnterpriseAssignmentRows.Add([pscustomobject]@{
                ApplicationDisplayName=$Application.displayName; AppId=$Application.appId; ServicePrincipalObjectId=$Sp.id
                PrincipalId=$Assignment.principalId; PrincipalDisplayName=$Assignment.principalDisplayName
                PrincipalType=$Assignment.principalType; AppRole=$RoleName; AssignmentId=$Assignment.id
                CreatedDateTime=Get-PropertyValue $Assignment 'createdDateTime'
            })
        }
        if (-not $SkipSignInActivity) {
            $Activity = Get-PropertyValue $Sp 'signInActivity'
            $SignInRows.Add([pscustomobject]@{
                ApplicationDisplayName = $Application.displayName
                AppId = $Application.appId
                ServicePrincipalObjectId = $Sp.id
                ServicePrincipalEnabled = $Sp.accountEnabled
                LastSignInDateTime = if ($Activity) { Get-PropertyValue $Activity 'lastSignInDateTime' } else { $null }
                LastDelegatedClientSignInDateTime = if ($Activity) { Get-PropertyValue $Activity 'lastDelegatedClientSignInDateTime' } else { $null }
                LastApplicationAuthenticationRequestDateTime = if ($Activity) { Get-PropertyValue $Activity 'lastApplicationAuthenticationRequestDateTime' } else { $null }
                CoverageStatus = if ($Activity) { 'Returned' } else { 'NotReturnedOrUnavailable' }
            })
        }
    }

    $AppOwnerIds = @($Owners | ForEach-Object { [string]$_.id })
    $SpOwnerIds = @($SpOwners | ForEach-Object { [string]$_.id })
    $OnlyApp = @($AppOwnerIds | Where-Object { $_ -notin $SpOwnerIds })
    $OnlySp = @($SpOwnerIds | Where-Object { $_ -notin $AppOwnerIds })
    if ($OnlyApp.Count -gt 0 -or $OnlySp.Count -gt 0) {
        $OwnershipMismatchRows.Add([pscustomobject]@{
            ApplicationDisplayName = $Application.displayName
            AppId = $Application.appId
            ApplicationOnlyOwnerIds = Join-Values $OnlyApp
            ServicePrincipalOnlyOwnerIds = Join-Values $OnlySp
            ApplicationOwnerCount = $Owners.Count
            ServicePrincipalOwnerCount = $SpOwners.Count
            Disposition = 'Review ownership intent; application and service-principal ownership differ.'
        })
    }
    if ($Owners.Count -eq 0) {
        $OwnerlessRows.Add([pscustomobject]@{
            ApplicationDisplayName = $Application.displayName
            AppId = $Application.appId
            ApplicationObjectId = $Application.id
            ServicePrincipalObjectId = if ($Sp) { $Sp.id } else { '' }
            ServicePrincipalEnabled = if ($Sp) { $Sp.accountEnabled } else { $null }
            PasswordCredentialCount = @($Application.passwordCredentials).Count
            CertificateCredentialCount = @($Application.keyCredentials).Count
            LastSignInDateTime = if ($Sp -and (Get-PropertyValue $Sp 'signInActivity')) { Get-PropertyValue (Get-PropertyValue $Sp 'signInActivity') 'lastSignInDateTime' } else { $null }
            Disposition = 'Governance review; ownerless does not alone prove the application is stale.'
        })
    }

    $AppPerms = @($GraphPermissionRows | Where-Object { $_.AppId -eq $Application.appId })
    $HighImpactPerms = @($AppPerms | Where-Object HighImpact)
    if ($Sp -and -not $Sp.accountEnabled -and $AppPerms.Count -gt 0) {
        $DisabledPrivilegedRows.Add([pscustomobject]@{
            ApplicationDisplayName = $Application.displayName
            AppId = $Application.appId
            ServicePrincipalObjectId = $Sp.id
            ServicePrincipalEnabled = $Sp.accountEnabled
            MicrosoftGraphApplicationPermissions = Join-Values (Get-PropertyValues -InputObject $AppPerms -PropertyName 'Permission')
            HighImpactPermissions = Join-Values (Get-PropertyValues -InputObject $HighImpactPerms -PropertyName 'Permission')
            Disposition = 'Review and remove residual grants if the workload is retired.'
        })
    }

    $EnabledNonAdminOwners = @()
    if ($RoleCoverageAvailable) {
        $EnabledNonAdminOwners = @(
            $Owners | Where-Object {
                $Enabled = Get-PropertyValue $_ 'accountEnabled'
                $Upn = Get-PropertyValue $_ 'userPrincipalName'
                $Upn -and $Enabled -eq $true -and -not $RolesByPrincipalId.ContainsKey([string]$_.id)
            }
        )
    }
    $Classification = 'RoutineReview'
    $Reason = 'No high-signal governance combination detected by this assessment.'
    if ($EnabledNonAdminOwners.Count -gt 0 -and $HighImpactPerms.Count -gt 0) {
        $Classification = 'ConfirmedHighRiskRelationship'
        $Reason = 'Enabled owner with no directly observed active Entra role controls an application whose service principal has high-impact Microsoft Graph application permissions.'
    } elseif ($Sp -and -not $Sp.accountEnabled -and $AppPerms.Count -gt 0) {
        $Classification = 'DecommissioningReview'
        $Reason = 'Disabled service principal retains Microsoft Graph application permissions.'
    } elseif ($Owners.Count -eq 0 -and $Sp -and $Sp.accountEnabled) {
        $Classification = 'OwnerlessActiveWorkloadReview'
        $Reason = 'Enabled local service principal is associated with an ownerless application registration.'
    } elseif ($IsMultitenant -and -not ($Lock -and (Get-PropertyValue $Lock 'isEnabled'))) {
        $Classification = 'AppInstanceLockCompatibilityReview'
        $Reason = 'Multitenant application does not have App Instance Property Lock enabled; applicability and compatibility require validation.'
    }
    $ClassificationRows.Add([pscustomobject]@{
        ApplicationDisplayName = $Application.displayName
        AppId = $Application.appId
        ApplicationObjectId = $Application.id
        ServicePrincipalObjectId = if ($Sp) { $Sp.id } else { '' }
        Classification = $Classification
        Reason = $Reason
        EnabledNonAdminOwnerCount = $EnabledNonAdminOwners.Count
        EnabledNonAdminOwners = Join-Values ($EnabledNonAdminOwners | ForEach-Object { Get-PropertyValue $_ 'userPrincipalName' })
        HighImpactGraphApplicationPermissions = Join-Values (Get-PropertyValues -InputObject $HighImpactPerms -PropertyName 'Permission')
        EvidenceLimitation = if ($RoleCoverageAvailable) { 'Direct active roles only. Business requirement, exploitability, PIM eligibility, transitive role membership, and operational ownership require separate validation.' } else { 'Role-assignment coverage unavailable. Business requirement, exploitability, PIM eligibility, transitive role membership, and operational ownership require separate validation.' }
    })
}

Write-Stage 'Building combined application and service-principal inventory.'
foreach ($AppRow in $AppInventoryRows.ToArray()) {
    $CombinedInventoryRows.Add([pscustomobject]@{
        ObjectType                        = 'ApplicationRegistration'
        DisplayName                       = $AppRow.DisplayName
        ApplicationClientId               = $AppRow.ApplicationClientId
        DirectoryObjectId                 = $AppRow.ApplicationObjectId
        AccountEnabled                    = ''
        ServicePrincipalType              = ''
        SignInAudience                    = $AppRow.SignInAudience
        CreatedDateTime                   = $AppRow.CreatedDateTime
        Publisher                         = $AppRow.PublisherDomain
        VerifiedPublisher                 = $AppRow.VerifiedPublisher
        PasswordCredentialCount           = $AppRow.PasswordCredentialCount
        KeyCredentialCount                = $AppRow.KeyCredentialCount
        DisabledByMicrosoftStatus         = $AppRow.DisabledByMicrosoftStatus
        HomeApplicationRegistrationPresent = $true
        OwnershipCategory                 = 'Tenant-owned application registration'
    })
}
foreach ($SpRow in $SpInventoryRows.ToArray()) {
    $CombinedInventoryRows.Add([pscustomobject]@{
        ObjectType                        = 'ServicePrincipal'
        DisplayName                       = $SpRow.DisplayName
        ApplicationClientId               = $SpRow.ApplicationClientId
        DirectoryObjectId                 = $SpRow.ServicePrincipalObjectId
        AccountEnabled                    = $SpRow.AccountEnabled
        ServicePrincipalType              = $SpRow.ServicePrincipalType
        SignInAudience                    = $SpRow.SignInAudience
        CreatedDateTime                   = $SpRow.CreatedDateTime
        Publisher                         = $SpRow.PublisherName
        VerifiedPublisher                 = $SpRow.VerifiedPublisher
        PasswordCredentialCount           = $SpRow.PasswordCredentialCount
        KeyCredentialCount                = $SpRow.KeyCredentialCount
        DisabledByMicrosoftStatus         = $SpRow.DisabledByMicrosoftStatus
        HomeApplicationRegistrationPresent = $SpRow.HomeApplicationRegistrationPresent
        OwnershipCategory                 = $SpRow.OwnershipCategory
    })
}
Write-Pass "Combined inventory rows: $($CombinedInventoryRows.Count)"

Write-Stage 'Resolving active role-assignment principals.'
foreach ($Assignment in $RoleAssignments) {
    $PrincipalId = [string]$Assignment.principalId
    $PrincipalType = 'Unknown'
    $PrincipalName = ''
    if ($ServicePrincipalById.ContainsKey($PrincipalId)) {
        $PrincipalType = 'ServicePrincipal'
        $PrincipalName = $ServicePrincipalById[$PrincipalId].displayName
    }
    $RoleAssignmentRows.Add([pscustomobject]@{
        AssignmentId = Get-PropertyValue $Assignment 'id'
        PrincipalId = $PrincipalId
        PrincipalType = $PrincipalType
        PrincipalDisplayName = $PrincipalName
        RoleDefinitionId = Get-PropertyValue $Assignment 'roleDefinitionId'
        RoleName = if ($RoleDefinitionById.ContainsKey([string](Get-PropertyValue $Assignment 'roleDefinitionId'))) { Get-PropertyValue $RoleDefinitionById[[string](Get-PropertyValue $Assignment 'roleDefinitionId')] 'displayName' } else { '' }
        DirectoryScopeId = Get-PropertyValue $Assignment 'directoryScopeId'
        AppScopeId = Get-PropertyValue $Assignment 'appScopeId'
    })
}

if ($AppInventoryRows.Count -ne $Applications.Count) {
    throw "Application inventory parity failure: collected $($Applications.Count), exported $($AppInventoryRows.Count)."
}
if ($SpInventoryRows.Count -ne $ServicePrincipals.Count) {
    throw "Service-principal inventory parity failure: collected $($ServicePrincipals.Count), exported $($SpInventoryRows.Count)."
}
$ExpectedCombinedInventoryRows = $Applications.Count + $ServicePrincipals.Count
if ($CombinedInventoryRows.Count -ne $ExpectedCombinedInventoryRows) {
    throw "Combined inventory parity failure: expected $ExpectedCombinedInventoryRows, exported $($CombinedInventoryRows.Count)."
}
Write-Pass "Inventory parity verified: $($Applications.Count) applications + $($ServicePrincipals.Count) service principals = $($CombinedInventoryRows.Count) combined rows."

$SummaryRows = @(
    [pscustomobject]@{ Metric='ScriptVersion'; Value=$ScriptVersion; Interpretation='Assessment version' },
    [pscustomobject]@{ Metric='GeneratedUtc'; Value=[datetime]::UtcNow.ToString('o'); Interpretation='Evidence generation time' },
    [pscustomobject]@{ Metric='Identity'; Value=$AssessmentIdentity; Interpretation='Signed-in identity used for collection' },
    [pscustomobject]@{ Metric='TenantId'; Value=$AssessmentTenantId; Interpretation='Tenant assessed' },
    [pscustomobject]@{ Metric='AuthenticationClient'; Value=$AuthenticationClient; Interpretation='OAuth client used to acquire or supply the Microsoft Graph token' },
    [pscustomobject]@{ Metric='Applications'; Value=$Applications.Count; Interpretation='Application registrations collected' },
    [pscustomobject]@{ Metric='OldApplications'; Value=$OldAppRows.Count; Interpretation="Applications at least $OldAppAgeDays days old; review lead only" },
    [pscustomobject]@{ Metric='AllApplicationPermissions'; Value=$AllApplicationPermissionRows.Count; Interpretation='Application permissions across all resource APIs' },
    [pscustomobject]@{ Metric='EnterpriseAssignments'; Value=$EnterpriseAssignmentRows.Count; Interpretation='Users, groups, or service principals assigned to local enterprise applications' },
    [pscustomobject]@{ Metric='ServicePrincipals'; Value=$ServicePrincipals.Count; Interpretation='Service principals collected' },
    [pscustomobject]@{ Metric='ServicePrincipalInventoryRows'; Value=$SpInventoryRows.Count; Interpretation='Must equal ServicePrincipals for full inventory parity' },
    [pscustomobject]@{ Metric='CombinedInventoryRows'; Value=$CombinedInventoryRows.Count; Interpretation='Application registrations plus all service principals' },
    [pscustomobject]@{ Metric='Owners'; Value=$OwnerRows.Count; Interpretation='Application and service-principal ownership rows' },
    [pscustomobject]@{ Metric='GraphApplicationPermissions'; Value=$GraphPermissionRows.Count; Interpretation='Microsoft Graph app-only grants' },
    [pscustomobject]@{ Metric='HighImpactGraphApplicationPermissions'; Value=@($GraphPermissionRows | Where-Object HighImpact).Count; Interpretation='Prioritization lead, not final severity' },
    [pscustomobject]@{ Metric='DelegatedGrants'; Value=$DelegatedGrantRows.Count; Interpretation='OAuth2 delegated permission grants' },
    [pscustomobject]@{ Metric='Credentials'; Value=$CredentialRows.Count; Interpretation='Application password and certificate metadata only' },
    [pscustomobject]@{ Metric='OwnerlessApplications'; Value=$OwnerlessRows.Count; Interpretation='Governance review candidates' },
    [pscustomobject]@{ Metric='ConfirmedHighRiskRelationships'; Value=@($ClassificationRows | Where-Object Classification -eq 'ConfirmedHighRiskRelationship').Count; Interpretation='Requires business and permission validation before remediation' },
    [pscustomobject]@{ Metric='Errors'; Value=$Errors.Count; Interpretation='Coverage limitations and failed queries' }
)

$DataSets = [ordered]@{
    'Summary' = $SummaryRows
    'Application Inventory' = $AppInventoryRows.ToArray()
    'Service Principal Inventory' = $SpInventoryRows.ToArray()
    'Combined Inventory' = $CombinedInventoryRows.ToArray()
    'Old Applications' = $OldAppRows.ToArray()
    'App-SP Status' = $StatusRows.ToArray()
    'Owners' = $OwnerRows.ToArray()
    'Owner Active Roles' = $OwnerRoleRows.ToArray()
    'All App Permissions' = $AllApplicationPermissionRows.ToArray()
    'Graph App Permissions' = $GraphPermissionRows.ToArray()
    'Delegated Grants' = $DelegatedGrantRows.ToArray()
    'Enterprise Assignments' = $EnterpriseAssignmentRows.ToArray()
    'Credentials' = $CredentialRows.ToArray()
    'Ownerless Apps' = $OwnerlessRows.ToArray()
    'Disabled With Grants' = $DisabledPrivilegedRows.ToArray()
    'Ownership Mismatches' = $OwnershipMismatchRows.ToArray()
    'App Instance Lock' = $LockRows.ToArray()
    'Publisher Verification' = $PublisherRows.ToArray()
    'Multitenant Apps' = $MultitenantRows.ToArray()
    'User Assignment' = $AssignmentRows.ToArray()
    'Sign-In Activity' = $SignInRows.ToArray()
    'Role Assignments' = $RoleAssignmentRows.ToArray()
    'Classifications' = $ClassificationRows.ToArray()
    'Errors' = $Errors.ToArray()
}

Write-Stage 'Writing the multi-sheet Excel workbook.'
if (Test-Path -LiteralPath $WorkbookPath) { Remove-Item -LiteralPath $WorkbookPath -Force }
$FirstWorksheet = $true
foreach ($SheetName in $DataSets.Keys) {
    $Rows = @($DataSets[$SheetName])
    if ($Rows.Count -eq 0) {
        $Rows = if ($SheetName -eq 'Errors') { @([pscustomobject]@{ Status='No collection errors recorded'; Note='All implemented collectors completed without a recorded coverage or request error.' }) } else { @([pscustomobject]@{ Status='No records returned'; Note='This can mean no matching objects, unavailable permissions, unsupported data, or a coverage limitation. Review the Errors sheet.' }) }
    }

    $ExportParameters = @{
        Path = $WorkbookPath
        WorksheetName = $SheetName
        TableName = (($SheetName -replace '[^A-Za-z0-9]','') + 'Table')
        TableStyle = 'Medium2'
        AutoSize = $true
        AutoFilter = $true
        FreezeTopRow = $true
        BoldTopRow = $true
    }
    if (-not $FirstWorksheet) { $ExportParameters.Append = $true }
    $Rows | Export-Excel @ExportParameters
    $FirstWorksheet = $false
}

Write-Stage 'Applying workbook presentation formatting.'
$Excel = Open-ExcelPackage -Path $WorkbookPath
try {
foreach ($Worksheet in $Excel.Workbook.Worksheets) {
    $Worksheet.View.ShowGridLines = $false
    $Worksheet.Row(1).Height = 24
    if ($Worksheet.Dimension) {
        $Worksheet.Cells[$Worksheet.Dimension.Address].Style.VerticalAlignment = 'Top'
        $Worksheet.Cells[$Worksheet.Dimension.Address].Style.WrapText = $false
        $Worksheet.Cells[1,1,1,$Worksheet.Dimension.End.Column].Style.Font.Bold = $true
        $Worksheet.Cells[1,1,1,$Worksheet.Dimension.End.Column].Style.Font.Color.SetColor([System.Drawing.Color]::White)
        $Worksheet.Cells[1,1,1,$Worksheet.Dimension.End.Column].Style.Fill.PatternType = 'Solid'
        $Worksheet.Cells[1,1,1,$Worksheet.Dimension.End.Column].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(31,78,121))
        # EPPlus worksheets do not expose a Columns collection. Address each used
        # column by its numeric index through Worksheet.Column().
        for ($ColumnIndex = 1; $ColumnIndex -le $Worksheet.Dimension.End.Column; $ColumnIndex++) {
            $Column = $Worksheet.Column($ColumnIndex)
            if ($Column.Width -gt 60) { $Column.Width = 60 }
            if ($Column.Width -lt 12) { $Column.Width = 12 }
        }
    }
}
}
finally {
    if ($null -ne $Excel) { Close-ExcelPackage $Excel }
}

$EvidencePackage = [ordered]@{}
foreach ($Name in $DataSets.Keys) { $EvidencePackage[$Name] = @($DataSets[$Name]) }
$EvidencePackage | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $JsonPath -Encoding utf8

# Remove in-memory bearer-token references before completion.
$GraphAccessToken = $null
$SecureGraphAccessToken = $null
if ($null -ne $TokenResponse) { $TokenResponse.accessToken = $null }
$Claims = $null

$Hash = Get-FileHash -LiteralPath $WorkbookPath -Algorithm SHA256
$CompletedUtc = [datetime]::UtcNow
Write-Host ''
Write-Pass 'Assessment completed.'
Write-Pass "Workbook: $WorkbookPath"
Write-Pass "JSON evidence: $JsonPath"
Write-Pass "Workbook SHA-256: $($Hash.Hash)"
Write-Pass ('Duration: {0:n1} minutes' -f (($CompletedUtc - $StartedUtc).TotalMinutes))
Write-Host ''
