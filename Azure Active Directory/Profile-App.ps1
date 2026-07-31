#requires -Version 5.1
<#
.SYNOPSIS
Creates a governance-ready profile for one Microsoft Entra application by application client ID.

.DESCRIPTION
Profiles the application registration and tenant service principal associated with one AppId.
The script reuses the current Microsoft Graph session, is read-only, requests no new consent,
installs no modules, and does not disconnect the existing session.

Outputs include application and service-principal metadata, owners, credential metadata,
application permissions, delegated OAuth grants, enterprise application assignments, recent
interactive sign-ins, recent service-principal sign-ins when available, warnings, and a complete
JSON profile.

.PARAMETER TargetAppId
Application client ID to profile.

.PARAMETER OutputPath
Directory for timestamped output files. Defaults to the script directory.

.PARAMETER SignInLookbackDays
Number of days of sign-in history requested. Defaults to 30.

.PARAMETER NoSignIns
Skips interactive and service-principal sign-in retrieval.

.EXAMPLE
.\Profile-App.ps1 -TargetAppId '36e899a8-29fe-402b-abeb-d4f3535e702f'

.EXAMPLE
.\Profile-App.ps1 -TargetAppId '4427e48b-14cb-46ae-bfe8-b34aec39c694' -SignInLookbackDays 60

.EXAMPLE
.\Profile-App.ps1 -TargetAppId 'd586270a-ba25-43c7-a710-c5bea434fddb' -NoSignIns

.NOTES
Requires Get-MgContext and Invoke-MgGraphRequest from Microsoft.Graph.Authentication.
Sign-in visibility depends on the permissions, directory role, licensing, and retention available
to the existing Graph session. Missing optional datasets are recorded without aborting the profile.
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
    [ValidateRange(1, 180)]
    [int]$SignInLookbackDays = 30,

    [Parameter()]
    [switch]$NoSignIns
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-OptionalProperty {
    [CmdletBinding()]
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
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value).Trim().Trim('{}').ToLowerInvariant()
}

function ConvertTo-UtcText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return '' }
    try { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    catch { return [string]$Value }
}

function ConvertTo-SafeFileName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)
    $safe = $Value
    foreach ($character in [System.IO.Path]::GetInvalidFileNameChars()) {
        $safe = $safe.Replace([string]$character, '_')
    }
    $safe = ($safe -replace '\s+', '-').Trim('-').Trim()
    if ([string]::IsNullOrWhiteSpace($safe)) { return 'application' }
    return $safe
}

function Get-GraphCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri -OutputType PSObject
        $value = Get-OptionalProperty -InputObject $response -Name 'value' -DefaultValue $null
        if ($null -ne $value) {
            foreach ($item in @($value)) {
                if ($null -ne $item) { $items.Add($item) }
            }
        } else {
            $responseValueProperty = $response.PSObject.Properties['value']
            if ($null -eq $responseValueProperty -and $null -ne $response) {
                $items.Add($response)
            }
        }
        $nextUri = [string](Get-OptionalProperty -InputObject $response -Name '@odata.nextLink')
    }
    return $items.ToArray()
}

function Invoke-OptionalGraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$DataSet,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Warnings
    )
    try { return @(Get-GraphCollection -Uri $Uri) }
    catch {
        $status = ''
        if ($null -ne $_.Exception.Response) {
            $status = [string](Get-OptionalProperty -InputObject $_.Exception.Response -Name 'StatusCode')
        }
        $message = "$DataSet could not be retrieved"
        if ($status) { $message += " (HTTP $status)" }
        $message += ": $($_.Exception.Message)"
        $Warnings.Add([pscustomobject]@{ DataSet=$DataSet; Message=$message })
        Write-Warning $message
        return @()
    }
}

function Export-CsvWithHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string[]]$Headers,
        [Parameter(Mandatory)][string]$LiteralPath
    )
    if (@($Rows).Count -gt 0) {
        $Rows | Select-Object -Property $Headers | Export-Csv -LiteralPath $LiteralPath -NoTypeInformation -Encoding UTF8
        return
    }
    $template = [ordered]@{}
    foreach ($header in $Headers) { $template[$header] = '' }
    $headerLine = ([pscustomobject]$template | ConvertTo-Csv -NoTypeInformation)[0]
    Set-Content -LiteralPath $LiteralPath -Value $headerLine -Encoding UTF8
}

function Resolve-DirectoryObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][hashtable]$Cache,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Warnings
    )
    $id = ConvertTo-NormalizedId $ObjectId
    if ($Cache.ContainsKey($id)) { return $Cache[$id] }
    try {
        $object = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$id" -OutputType PSObject
        $Cache[$id] = $object
        return $object
    } catch {
        $Warnings.Add([pscustomobject]@{ DataSet='Directory object resolution'; Message="Could not resolve directory object ${id}: $($_.Exception.Message)" })
        $fallback = [pscustomobject]@{ id=$id; displayName=''; userPrincipalName=''; '@odata.type'='' }
        $Cache[$id] = $fallback
        return $fallback
    }
}

function Resolve-ResourceServicePrincipal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResourceId,
        [Parameter(Mandatory)][hashtable]$Cache,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Warnings,
        [string]$FallbackDisplayName = ''
    )
    $id = ConvertTo-NormalizedId $ResourceId
    if ([string]::IsNullOrWhiteSpace($id)) {
        return [pscustomobject]@{ id=''; appId=''; displayName=$FallbackDisplayName; appRoles=@(); oauth2PermissionScopes=@() }
    }
    if ($Cache.ContainsKey($id)) { return $Cache[$id] }
    try {
        # Braces deliberately delimit ${id} before the URI query-string question mark.
        $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/${id}?`$select=id,appId,displayName,appRoles,oauth2PermissionScopes"
        $resource = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        $Cache[$id] = $resource
        return $resource
    } catch {
        $Warnings.Add([pscustomobject]@{ DataSet='Resource service principal'; Message="Could not resolve resource service principal ${id}: $($_.Exception.Message)" })
        $fallback = [pscustomobject]@{ id=$id; appId=''; displayName=$FallbackDisplayName; appRoles=@(); oauth2PermissionScopes=@() }
        $Cache[$id] = $fallback
        return $fallback
    }
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
$directoryObjectCache = @{}
$resourceSpCache = @{}

Write-Host "Reusing Microsoft Graph session for $($context.Account). No new consent request will be made." -ForegroundColor Cyan
Write-Host "Tenant ID: $($context.TenantId) | Authentication: $($context.AuthType)" -ForegroundColor DarkGray
Write-Host "Profiling application client ID: $targetId" -ForegroundColor Cyan

$appFilter = [uri]::EscapeDataString("appId eq '$targetId'")
$appUri = "https://graph.microsoft.com/v1.0/applications?`$filter=$appFilter&`$select=id,appId,displayName,createdDateTime,signInAudience,publisherDomain,disabledByMicrosoftStatus,description,notes,identifierUris,web,spa,publicClient,passwordCredentials,keyCredentials,tags,api&`$top=2"
$spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$appFilter&`$select=id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,publisherName,verifiedPublisher,homepage,loginUrl,replyUrls,notificationEmailAddresses,preferredSingleSignOnMode,appRoleAssignmentRequired,createdDateTime,tags,appRoles,oauth2PermissionScopes&`$top=2"
$appResults = @(Get-GraphCollection -Uri $appUri)
$spResults = @(Get-GraphCollection -Uri $spUri)
if ($appResults.Count -gt 1 -or $spResults.Count -gt 1) { throw "Multiple objects returned for AppId $targetId." }
if ($appResults.Count -eq 0 -and $spResults.Count -eq 0) { throw "No application or service principal found for AppId $targetId." }
$app = if ($appResults.Count -eq 1) { $appResults[0] } else { $null }
$sp = if ($spResults.Count -eq 1) { $spResults[0] } else { $null }
$displayName = if ($null -ne $app) { [string](Get-OptionalProperty $app 'displayName' $targetId) } else { [string](Get-OptionalProperty $sp 'displayName' $targetId) }
$prefix = Join-Path $resolvedOutputPath "app-profile-$(ConvertTo-SafeFileName $displayName)-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

$ownerRows = @()
$passwordRows = @()
$keyRows = @()
if ($null -ne $app) {
    $appObjectId = ConvertTo-NormalizedId (Get-OptionalProperty $app 'id')
    $ownerUri = "https://graph.microsoft.com/v1.0/applications/${appObjectId}/owners?`$select=id,displayName,userPrincipalName,mail,appId&`$top=999"
    $ownerRows = @(
        foreach ($owner in @(Invoke-OptionalGraphCollection $ownerUri 'Application owners' $warnings)) {
            [pscustomobject][ordered]@{
                ObjectId=Get-OptionalProperty $owner 'id'; ObjectType=([string](Get-OptionalProperty $owner '@odata.type')).Replace('#microsoft.graph.','')
                DisplayName=Get-OptionalProperty $owner 'displayName'; UserPrincipalName=Get-OptionalProperty $owner 'userPrincipalName'
                Mail=Get-OptionalProperty $owner 'mail'; ApplicationId=Get-OptionalProperty $owner 'appId'
            }
        }
    )
    $passwordRows = @(
        foreach ($credential in @(Get-OptionalProperty $app 'passwordCredentials' @())) {
            $end = Get-OptionalProperty $credential 'endDateTime'
            [pscustomobject][ordered]@{
                CredentialType='Password'; DisplayName=Get-OptionalProperty $credential 'displayName'; KeyId=Get-OptionalProperty $credential 'keyId'
                Hint=Get-OptionalProperty $credential 'hint'; StartDateTimeUtc=ConvertTo-UtcText (Get-OptionalProperty $credential 'startDateTime')
                EndDateTimeUtc=ConvertTo-UtcText $end; Expired=if($end){([datetime]$end).ToUniversalTime() -lt [datetime]::UtcNow}else{$false}
                DaysRemaining=if($end){[math]::Floor((([datetime]$end).ToUniversalTime()-[datetime]::UtcNow).TotalDays)}else{''}
            }
        }
    )
    $keyRows = @(
        foreach ($credential in @(Get-OptionalProperty $app 'keyCredentials' @())) {
            $end = Get-OptionalProperty $credential 'endDateTime'
            [pscustomobject][ordered]@{
                CredentialType='Certificate'; DisplayName=Get-OptionalProperty $credential 'displayName'; KeyId=Get-OptionalProperty $credential 'keyId'
                KeyType=Get-OptionalProperty $credential 'type'; KeyUsage=Get-OptionalProperty $credential 'usage'; Thumbprint=Get-OptionalProperty $credential 'customKeyIdentifier'
                StartDateTimeUtc=ConvertTo-UtcText (Get-OptionalProperty $credential 'startDateTime'); EndDateTimeUtc=ConvertTo-UtcText $end
                Expired=if($end){([datetime]$end).ToUniversalTime() -lt [datetime]::UtcNow}else{$false}
                DaysRemaining=if($end){[math]::Floor((([datetime]$end).ToUniversalTime()-[datetime]::UtcNow).TotalDays)}else{''}
            }
        }
    )
}

$applicationPermissionRows=@(); $delegatedPermissionRows=@(); $assignmentRows=@(); $interactiveSignInRows=@(); $servicePrincipalSignInRows=@()
if ($null -ne $sp) {
    $spObjectId = ConvertTo-NormalizedId (Get-OptionalProperty $sp 'id')
    Write-Host 'Retrieving granted application permissions...' -ForegroundColor Cyan
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/${spObjectId}/appRoleAssignments?`$select=id,appRoleId,resourceId,resourceDisplayName,createdDateTime&`$top=999"
    $rawAppGrants = @(
        @(Invoke-OptionalGraphCollection $uri 'Application permissions' $warnings) |
            Where-Object {
                $null -ne $_ -and
                -not [string]::IsNullOrWhiteSpace([string](Get-OptionalProperty $_ 'id')) -and
                -not [string]::IsNullOrWhiteSpace([string](Get-OptionalProperty $_ 'appRoleId')) -and
                -not [string]::IsNullOrWhiteSpace([string](Get-OptionalProperty $_ 'resourceId'))
            }
    )
    foreach ($grant in $rawAppGrants) {
        $resourceId = ConvertTo-NormalizedId (Get-OptionalProperty $grant 'resourceId')
        $resource = Resolve-ResourceServicePrincipal $resourceId $resourceSpCache $warnings ([string](Get-OptionalProperty $grant 'resourceDisplayName'))
        $appRoleId = ConvertTo-NormalizedId (Get-OptionalProperty $grant 'appRoleId')
        $role = @(@(Get-OptionalProperty $resource 'appRoles' @()) | Where-Object { (ConvertTo-NormalizedId (Get-OptionalProperty $_ 'id')) -eq $appRoleId }) | Select-Object -First 1
        $applicationPermissionRows += [pscustomobject][ordered]@{
            ResourceDisplayName=Get-OptionalProperty $resource 'displayName' (Get-OptionalProperty $grant 'resourceDisplayName')
            ResourceAppId=Get-OptionalProperty $resource 'appId'; ResourceObjectId=$resourceId
            Permission=Get-OptionalProperty $role 'value' "Unresolved:$appRoleId"; PermissionDisplayName=Get-OptionalProperty $role 'displayName'
            AppRoleId=$appRoleId; GrantId=Get-OptionalProperty $grant 'id'; GrantedDateTimeUtc=ConvertTo-UtcText (Get-OptionalProperty $grant 'createdDateTime')
        }
    }
    if ($rawAppGrants.Count -gt 0 -and @($applicationPermissionRows | Where-Object { $_.Permission -notlike 'Unresolved:*' }).Count -eq 0) {
        $message = "Application permission grants were retrieved ($($rawAppGrants.Count)), but no permission names resolved. Review resource-principal warnings."
        $warnings.Add([pscustomobject]@{ DataSet='Application permission resolution'; Message=$message }); Write-Warning $message
    }

    Write-Host 'Retrieving delegated OAuth consent grants...' -ForegroundColor Cyan
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/${spObjectId}/oauth2PermissionGrants?`$select=id,clientId,consentType,principalId,resourceId,scope&`$top=999"
    $rawDelegatedGrants = @(Invoke-OptionalGraphCollection $uri 'Delegated permissions' $warnings)
    foreach ($grant in $rawDelegatedGrants) {
        $resourceId = ConvertTo-NormalizedId (Get-OptionalProperty $grant 'resourceId')
        $resource = Resolve-ResourceServicePrincipal $resourceId $resourceSpCache $warnings
        $principalId = ConvertTo-NormalizedId (Get-OptionalProperty $grant 'principalId')
        $principal = if($principalId){Resolve-DirectoryObject $principalId $directoryObjectCache $warnings}else{$null}
        $definitions = @(Get-OptionalProperty $resource 'oauth2PermissionScopes' @())
        foreach ($scope in @(@(([string](Get-OptionalProperty $grant 'scope')) -split '\s+') | Where-Object { $_ } | Sort-Object -Unique)) {
            $definition = @($definitions | Where-Object { [string](Get-OptionalProperty $_ 'value') -eq $scope }) | Select-Object -First 1
            $delegatedPermissionRows += [pscustomobject][ordered]@{
                ResourceDisplayName=Get-OptionalProperty $resource 'displayName'; ResourceAppId=Get-OptionalProperty $resource 'appId'; ResourceObjectId=$resourceId
                Permission=$scope; PermissionDisplayName=Get-OptionalProperty $definition 'adminConsentDisplayName'; ConsentType=Get-OptionalProperty $grant 'consentType'
                ConsentPrincipalId=$principalId; ConsentPrincipalName=Get-OptionalProperty $principal 'displayName'
                ConsentPrincipalUserPrincipalName=Get-OptionalProperty $principal 'userPrincipalName'; GrantId=Get-OptionalProperty $grant 'id'
            }
        }
    }

    Write-Host 'Retrieving enterprise application assignments...' -ForegroundColor Cyan
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/${spObjectId}/appRoleAssignedTo?`$select=id,appRoleId,principalId,principalDisplayName,principalType,createdDateTime&`$top=999"
    $targetRoles = @(Get-OptionalProperty $sp 'appRoles' @())
    foreach ($assignment in @(Invoke-OptionalGraphCollection $uri 'Enterprise application assignments' $warnings)) {
        $roleId = ConvertTo-NormalizedId (Get-OptionalProperty $assignment 'appRoleId')
        $role = @($targetRoles | Where-Object { (ConvertTo-NormalizedId (Get-OptionalProperty $_ 'id')) -eq $roleId }) | Select-Object -First 1
        $assignmentRows += [pscustomobject][ordered]@{
            PrincipalDisplayName=Get-OptionalProperty $assignment 'principalDisplayName'; PrincipalId=Get-OptionalProperty $assignment 'principalId'
            PrincipalType=Get-OptionalProperty $assignment 'principalType'; AppRole=Get-OptionalProperty $role 'value' $(if($roleId -eq '00000000-0000-0000-0000-000000000000'){'Default access'}else{"Unresolved:$roleId"})
            AppRoleDisplayName=Get-OptionalProperty $role 'displayName'; AssignmentId=Get-OptionalProperty $assignment 'id'
            CreatedDateTimeUtc=ConvertTo-UtcText (Get-OptionalProperty $assignment 'createdDateTime')
        }
    }

    if (-not $NoSignIns) {
        $startUtc=[datetime]::UtcNow.AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        Write-Host "Retrieving interactive sign-ins from the last $SignInLookbackDays days when available..." -ForegroundColor Cyan
        $filter=[uri]::EscapeDataString("appId eq '$targetId' and createdDateTime ge $startUtc")
        $uri="https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$select=id,createdDateTime,userDisplayName,userPrincipalName,userId,ipAddress,clientAppUsed,conditionalAccessStatus,status,resourceDisplayName,location,deviceDetail&`$top=999"
        foreach($signIn in @(Invoke-OptionalGraphCollection $uri 'Interactive sign-ins' $warnings)){
            $status=Get-OptionalProperty $signIn 'status' $null; $location=Get-OptionalProperty $signIn 'location' $null; $device=Get-OptionalProperty $signIn 'deviceDetail' $null
            $interactiveSignInRows += [pscustomobject][ordered]@{
                CreatedDateTimeUtc=ConvertTo-UtcText (Get-OptionalProperty $signIn 'createdDateTime'); UserDisplayName=Get-OptionalProperty $signIn 'userDisplayName'
                UserPrincipalName=Get-OptionalProperty $signIn 'userPrincipalName'; UserId=Get-OptionalProperty $signIn 'userId'; IPAddress=Get-OptionalProperty $signIn 'ipAddress'
                ClientAppUsed=Get-OptionalProperty $signIn 'clientAppUsed'; ResourceDisplayName=Get-OptionalProperty $signIn 'resourceDisplayName'
                ConditionalAccessStatus=Get-OptionalProperty $signIn 'conditionalAccessStatus'; ErrorCode=Get-OptionalProperty $status 'errorCode'; FailureReason=Get-OptionalProperty $status 'failureReason'
                City=Get-OptionalProperty $location 'city'; State=Get-OptionalProperty $location 'state'; CountryOrRegion=Get-OptionalProperty $location 'countryOrRegion'
                OperatingSystem=Get-OptionalProperty $device 'operatingSystem'; Browser=Get-OptionalProperty $device 'browser'; SignInId=Get-OptionalProperty $signIn 'id'
            }
        }

        Write-Host "Retrieving service principal sign-ins from the last $SignInLookbackDays days when available..." -ForegroundColor Cyan
        # Filter directly by servicePrincipalId. Do not reuse the appId filter used for interactive sign-ins.
        $spFilter=[uri]::EscapeDataString("servicePrincipalId eq '$spObjectId' and createdDateTime ge $startUtc")
        $uri="https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$spFilter&`$top=999"
        foreach($signIn in @(Invoke-OptionalGraphCollection $uri 'Service principal sign-ins' $warnings)){
            $status=Get-OptionalProperty $signIn 'status' $null
            $servicePrincipalSignInRows += [pscustomobject][ordered]@{
                CreatedDateTimeUtc=ConvertTo-UtcText (Get-OptionalProperty $signIn 'createdDateTime'); ServicePrincipalName=Get-OptionalProperty $signIn 'servicePrincipalName'
                ServicePrincipalId=Get-OptionalProperty $signIn 'servicePrincipalId'; IPAddress=Get-OptionalProperty $signIn 'ipAddress'
                ResourceDisplayName=Get-OptionalProperty $signIn 'resourceDisplayName'; ResourceId=Get-OptionalProperty $signIn 'resourceId'
                ConditionalAccessStatus=Get-OptionalProperty $signIn 'conditionalAccessStatus'; ErrorCode=Get-OptionalProperty $status 'errorCode'
                FailureReason=Get-OptionalProperty $status 'failureReason'; SignInEventTypes=@((Get-OptionalProperty $signIn 'signInEventTypes' @())) -join ';'
                SignInId=Get-OptionalProperty $signIn 'id'
            }
        }
    }
}

$web=if($null-ne$app){Get-OptionalProperty $app 'web' $null}else{$null}; $spa=if($null-ne$app){Get-OptionalProperty $app 'spa' $null}else{$null}
$publicClient=if($null-ne$app){Get-OptionalProperty $app 'publicClient' $null}else{$null}; $verifiedPublisher=if($null-ne$sp){Get-OptionalProperty $sp 'verifiedPublisher' $null}else{$null}
$summary=[pscustomobject][ordered]@{
    ProfileGeneratedUtc=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); TenantId=[string]$context.TenantId; AuthenticationType=[string]$context.AuthType
    ApplicationClientId=$targetId; DisplayName=$displayName; ApplicationRegistrationFound=($null-ne$app); ServicePrincipalFound=($null-ne$sp)
    ApplicationObjectId=if($null-ne$app){Get-OptionalProperty $app 'id'}else{''}; ServicePrincipalObjectId=if($null-ne$sp){Get-OptionalProperty $sp 'id'}else{''}
    AccountEnabled=if($null-ne$sp){Get-OptionalProperty $sp 'accountEnabled'}else{''}; ServicePrincipalType=if($null-ne$sp){Get-OptionalProperty $sp 'servicePrincipalType'}else{''}
    SignInAudience=if($null-ne$app){Get-OptionalProperty $app 'signInAudience'}else{''}; PublisherDomain=if($null-ne$app){Get-OptionalProperty $app 'publisherDomain'}else{''}
    PublisherName=if($null-ne$sp){Get-OptionalProperty $sp 'publisherName'}else{''}; VerifiedPublisher=Get-OptionalProperty $verifiedPublisher 'displayName'
    AppOwnerOrganizationId=if($null-ne$sp){Get-OptionalProperty $sp 'appOwnerOrganizationId'}else{''}; AppRoleAssignmentRequired=if($null-ne$sp){Get-OptionalProperty $sp 'appRoleAssignmentRequired'}else{''}
    PreferredSingleSignOnMode=if($null-ne$sp){Get-OptionalProperty $sp 'preferredSingleSignOnMode'}else{''}; HomepageUrl=Get-OptionalProperty $web 'homePageUrl' $(if($null-ne$sp){Get-OptionalProperty $sp 'homepage'}else{''})
    WebRedirectUris=@((Get-OptionalProperty $web 'redirectUris' @())); SpaRedirectUris=@((Get-OptionalProperty $spa 'redirectUris' @())); PublicClientRedirectUris=@((Get-OptionalProperty $publicClient 'redirectUris' @()))
    OwnerCount=@($ownerRows).Count; PasswordCredentialCount=@($passwordRows).Count; ExpiredPasswordCredentialCount=@($passwordRows|Where-Object Expired).Count
    KeyCredentialCount=@($keyRows).Count; ExpiredKeyCredentialCount=@($keyRows|Where-Object Expired).Count; ApplicationPermissionCount=@($applicationPermissionRows).Count
    UnresolvedApplicationPermissionCount=@($applicationPermissionRows|Where-Object{$_.Permission -like 'Unresolved:*'}).Count; DelegatedPermissionCount=@($delegatedPermissionRows).Count
    TenantWideDelegatedPermissionCount=@($delegatedPermissionRows|Where-Object ConsentType -eq 'AllPrincipals').Count; EnterpriseApplicationAssignmentCount=@($assignmentRows).Count
    InteractiveSignInCount=@($interactiveSignInRows).Count; ServicePrincipalSignInCount=@($servicePrincipalSignInRows).Count; SignInLookbackDays=if($NoSignIns){0}else{$SignInLookbackDays}; WarningCount=$warnings.Count
}
$profile=[pscustomobject][ordered]@{Summary=$summary;ApplicationRegistration=$app;ServicePrincipal=$sp;Owners=@($ownerRows);PasswordCredentials=@($passwordRows);KeyCredentials=@($keyRows);ApplicationPermissions=@($applicationPermissionRows);DelegatedPermissions=@($delegatedPermissionRows);EnterpriseAssignments=@($assignmentRows);InteractiveSignIns=@($interactiveSignInRows);ServicePrincipalSignIns=@($servicePrincipalSignInRows);Warnings=@($warnings)}

$paths=[ordered]@{Json="$prefix.json";Summary="$prefix-summary.csv";Owners="$prefix-owners.csv";Passwords="$prefix-password-credentials.csv";Keys="$prefix-key-credentials.csv";AppPermissions="$prefix-application-permissions.csv";DelegatedPermissions="$prefix-delegated-permissions.csv";Assignments="$prefix-enterprise-assignments.csv";InteractiveSignIns="$prefix-interactive-signins.csv";SpSignIns="$prefix-service-principal-signins.csv";Warnings="$prefix-warnings.csv"}
$profile|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $paths.Json -Encoding UTF8
$summary|Export-Csv -LiteralPath $paths.Summary -NoTypeInformation -Encoding UTF8
Export-CsvWithHeaders $ownerRows @('ObjectId','ObjectType','DisplayName','UserPrincipalName','Mail','ApplicationId') $paths.Owners
Export-CsvWithHeaders $passwordRows @('CredentialType','DisplayName','KeyId','Hint','StartDateTimeUtc','EndDateTimeUtc','Expired','DaysRemaining') $paths.Passwords
Export-CsvWithHeaders $keyRows @('CredentialType','DisplayName','KeyId','KeyType','KeyUsage','Thumbprint','StartDateTimeUtc','EndDateTimeUtc','Expired','DaysRemaining') $paths.Keys
Export-CsvWithHeaders $applicationPermissionRows @('ResourceDisplayName','ResourceAppId','ResourceObjectId','Permission','PermissionDisplayName','AppRoleId','GrantId','GrantedDateTimeUtc') $paths.AppPermissions
Export-CsvWithHeaders $delegatedPermissionRows @('ResourceDisplayName','ResourceAppId','ResourceObjectId','Permission','PermissionDisplayName','ConsentType','ConsentPrincipalId','ConsentPrincipalName','ConsentPrincipalUserPrincipalName','GrantId') $paths.DelegatedPermissions
Export-CsvWithHeaders $assignmentRows @('PrincipalDisplayName','PrincipalId','PrincipalType','AppRole','AppRoleDisplayName','AssignmentId','CreatedDateTimeUtc') $paths.Assignments
Export-CsvWithHeaders $interactiveSignInRows @('CreatedDateTimeUtc','UserDisplayName','UserPrincipalName','UserId','IPAddress','ClientAppUsed','ResourceDisplayName','ConditionalAccessStatus','ErrorCode','FailureReason','City','State','CountryOrRegion','OperatingSystem','Browser','SignInId') $paths.InteractiveSignIns
Export-CsvWithHeaders $servicePrincipalSignInRows @('CreatedDateTimeUtc','ServicePrincipalName','ServicePrincipalId','IPAddress','ResourceDisplayName','ResourceId','ConditionalAccessStatus','ErrorCode','FailureReason','SignInEventTypes','SignInId') $paths.SpSignIns
Export-CsvWithHeaders @($warnings) @('DataSet','Message') $paths.Warnings

Write-Host ''
Write-Host 'Application profile complete.' -ForegroundColor Green
Write-Host "Display name                         : $displayName"
Write-Host "Application registration found      : $($summary.ApplicationRegistrationFound)"
Write-Host "Service principal found             : $($summary.ServicePrincipalFound)"
Write-Host "Account enabled                      : $($summary.AccountEnabled)"
Write-Host "Owners                               : $($summary.OwnerCount)"
Write-Host "Password credentials                 : $($summary.PasswordCredentialCount) ($($summary.ExpiredPasswordCredentialCount) expired)"
Write-Host "Certificate credentials              : $($summary.KeyCredentialCount) ($($summary.ExpiredKeyCredentialCount) expired)"
Write-Host "Application permission grants        : $($summary.ApplicationPermissionCount)"
Write-Host "  Unresolved application permissions : $($summary.UnresolvedApplicationPermissionCount)"
Write-Host "Delegated permission rows            : $($summary.DelegatedPermissionCount)"
Write-Host "  Tenant-wide delegated rows         : $($summary.TenantWideDelegatedPermissionCount)"
Write-Host "Enterprise application assignments   : $($summary.EnterpriseApplicationAssignmentCount)"
Write-Host "Interactive sign-ins                 : $($summary.InteractiveSignInCount)"
Write-Host "Service principal sign-ins           : $($summary.ServicePrincipalSignInCount)"
Write-Host "Warnings / unavailable data sets     : $($summary.WarningCount)"
Write-Host "Governance JSON profile              : $($paths.Json)"
Write-Host "Summary CSV                          : $($paths.Summary)"
Write-Host "Application permissions CSV          : $($paths.AppPermissions)"
Write-Host "Delegated permissions CSV            : $($paths.DelegatedPermissions)"
Write-Host "Assignments CSV                      : $($paths.Assignments)"
Write-Host "Warnings CSV                         : $($paths.Warnings)"
Write-Host ''
Write-Host 'Interpret findings with owner, usage, credential, sign-in, and least-privilege evidence before remediation.' -ForegroundColor Yellow
