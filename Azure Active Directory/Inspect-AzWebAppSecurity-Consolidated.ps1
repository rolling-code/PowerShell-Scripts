<#

USAGE
	run after az login:
    .\Inspect-AzWebAppSecurity-Consolidated.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -AppName <app> [-MySqlServer <mysqlName> -MySqlRg <mysqlRg>] [-AcrName <acrName>] [-VaultName <vaultName>] [-CheckVNet] [-RunKuduProbe]

#>

param(
    [Parameter(Mandatory=$true)][string]$SubscriptionId,
    [Parameter(Mandatory=$true)][string]$ResourceGroup,
    [Parameter(Mandatory=$true)][string]$AppName,
    [string]$MySqlServer,
    [string]$MySqlRg,
    [string]$AcrName,
    [string]$VaultName,
    [switch]$CheckVNet,
    [switch]$RunKuduProbe
)

# Trim inputs
$SubscriptionId = $SubscriptionId.Trim()
$ResourceGroup   = $ResourceGroup.Trim()
$AppName         = $AppName.Trim()

# Preflight: ensure az exists and set subscription
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: az CLI not found. Install Azure CLI and run az login." -ForegroundColor Red
    exit 1
}
az account set --subscription $SubscriptionId 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to set subscription $SubscriptionId" -ForegroundColor Red
    exit 1
}

# Robust lookup: try direct show, otherwise search subscription for matching app
$webappRaw = az webapp show -g $ResourceGroup -n $AppName --output json 2>$null
if ($LASTEXITCODE -ne 0 -or -not $webappRaw) {
    Write-Host "=== Resource lookup fallback: searching subscription for matching web app ===" -ForegroundColor Cyan
    $candidatesRaw = az resource list --subscription $SubscriptionId --resource-type "Microsoft.Web/sites" --query "[].{name:name,rg:resourceGroup,id:id}" --output json 2>$null
    if ($candidatesRaw) {
        $candidates = $candidatesRaw | ConvertFrom-Json
        $match = $candidates | Where-Object { $_.name.ToLower() -eq $AppName.ToLower() } | Select-Object -First 1
        if ($match) {
            $webappRaw = az webapp show -g $match.rg -n $match.name --output json 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $webappRaw) {
                Write-Host "ERROR: Found candidate but unable to retrieve details for $($match.name) in $($match.rg)." -ForegroundColor Red
                exit 1
            } else {
                $webapp = $webappRaw | ConvertFrom-Json
            }
        } else {
            Write-Host "ERROR: Web App $AppName not found in subscription $SubscriptionId." -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "ERROR: Unable to list web apps in subscription $SubscriptionId." -ForegroundColor Red
        exit 1
    }
} else {
    $webapp = $webappRaw | ConvertFrom-Json
}

# 1) Querying App Service details
Write-Host "=== Querying App Service details ===" -ForegroundColor Cyan
$raw = az webapp show -g $webapp.resourceGroup -n $AppName --output json 2>$null
if ($LASTEXITCODE -ne 0 -or -not $raw) {
    Write-Host "[FAIL] Unable to retrieve Web App details" -ForegroundColor Red
    Write-Host "       Check resource group, app name, and permissions." -ForegroundColor Yellow
} else {
    $obj = $raw | ConvertFrom-Json
    Write-Host "Default hostnames: $($obj.defaultHostName)"
    Write-Host "State: $($obj.state)"
    Write-Host "Kind: $($obj.kind)"
    Write-Host "App Service Plan: $($obj.serverFarmId)"
    Write-Host "[PASS] App Service details retrieved" -ForegroundColor Green
}

# 2) Outbound and possible inbound endpoints
Write-Host "`n=== Outbound and possible inbound endpoints ===" -ForegroundColor Cyan
$raw = az webapp show -g $webapp.resourceGroup -n $AppName --query '{outbound:outboundIpAddresses, hostnames:enabledHostNames}' --output json 2>$null
if ($LASTEXITCODE -ne 0 -or -not $raw) {
    Write-Host "[FAIL] Unable to retrieve outbound IPs/hostnames" -ForegroundColor Red
} else {
    $o = $raw | ConvertFrom-Json
    Write-Host "Outbound IPs: $($o.outbound)"
    if ($o.hostnames) { Write-Host "Hostnames: $($o.hostnames -join ' ')" } else { Write-Host "Hostnames: (none reported)" }
    Write-Host "[PASS] Outbound/hostnames retrieved" -ForegroundColor Green
}

# 3) Publishing profiles and credentials (FTP, FTPS, MSDeploy, SCM)
Write-Host "`n=== Publishing profiles and credentials (FTP, FTPS, MSDeploy, SCM) ===" -ForegroundColor Cyan
$profilesRaw = az webapp deployment list-publishing-profiles -g $webapp.resourceGroup -n $AppName --output json 2>$null
if ($LASTEXITCODE -ne 0 -or -not $profilesRaw) {
    Write-Host "[FAIL] Unable to retrieve publishing profiles" -ForegroundColor Red
} else {
    $profiles = $profilesRaw | ConvertFrom-Json
    foreach ($p in $profiles) {
        $method = $p.publishMethod
        $url = $p.publishUrl
        $user = $p.userName
        Write-Host ("Publish method: {0}  - publishUrl: {1}  - userName: {2}" -f $method, $url, $user)
    }
    $credsRaw = az webapp deployment list-publishing-credentials -g $webapp.resourceGroup -n $AppName --output json 2>$null
    if ($LASTEXITCODE -eq 0 -and $credsRaw) {
        $creds = $credsRaw | ConvertFrom-Json
        $pubUser = $creds.publishingUserName
        $pubPass = $creds.publishingPassword
        Write-Host "Kudu (SCM) URL: https://$AppName.scm.azurewebsites.net"
        Write-Host "Useful Kudu endpoints:"
        $kudu = "https://$AppName.scm.azurewebsites.net"
        Write-Host " - $kudu/"
        Write-Host " - $kudu/api/settings"
        Write-Host " - $kudu/api/vfs/site/wwwroot/ (file browser)"
        Write-Host " - $kudu/api/zip/site/wwwroot (download site content as zip)"
        Write-Host " - $kudu/api/processes (process explorer)"
        Write-Host " - $kudu/api/command (run commands)"
        Write-Host " - $kudu/api/diagnostics/trace (trace logs)"
        Write-Host " - $kudu/api/diagnostics/collect (collect diagnostic dump)"
        Write-Host "Publishing username: $pubUser"
        if ($pubPass) { Write-Host "Publishing password: $pubPass" } else { Write-Host "Publishing password: (not returned)" }
        Write-Host "[PASS] Publishing profiles and credentials retrieved" -ForegroundColor Green
    } else {
        Write-Host "Publishing credentials not available or insufficient permissions to list them."
        Write-Host "[FAIL] Publishing credentials not available" -ForegroundColor Red
    }
}

# 4) Basic App Service checks (HTTPS Only, TLS, Easy Auth, Managed Identity, AlwaysOn)
Write-Host "`n=== Basic App Service checks ===" -ForegroundColor Cyan
$httpsJson = az webapp show -g $webapp.resourceGroup -n $AppName --query '{httpsOnly:httpsOnly}' --output json 2>$null
$cfgJson = az webapp config show -g $webapp.resourceGroup -n $AppName --query '{minTlsVersion:minTlsVersion,detailedErrorLoggingEnabled:detailedErrorLoggingEnabled,ftpsState:ftpsState,scmType:scmType,alwaysOn:alwaysOn}' --output json 2>$null
$authJson = az webapp auth show -g $webapp.resourceGroup -n $AppName --output json 2>$null
$idJson = az webapp identity show -g $webapp.resourceGroup -n $AppName --output json 2>$null

$https = $null; $minTls = $null; $ftpsState = $null; $scmType = $null; $alwaysOn = $null
if ($httpsJson) { $https = ($httpsJson | ConvertFrom-Json).httpsOnly }
if ($cfgJson) { $cfg = $cfgJson | ConvertFrom-Json; $minTls = $cfg.minTlsVersion; $ftpsState = $cfg.ftpsState; $scmType = $cfg.scmType; $alwaysOn = $cfg.alwaysOn }

if ($https -eq $true) { Write-Host "[PASS] HTTPS Only must be ON" -ForegroundColor Green; Write-Host "       httpsOnly = True" -ForegroundColor Yellow } else { Write-Host "[FAIL] HTTPS Only must be ON" -ForegroundColor Red; Write-Host "       httpsOnly = $https" -ForegroundColor Yellow }

Write-Host "Checking minimum TLS version"
if ($minTls -in @("1.2","1.3")) { Write-Host "[PASS] Minimum TLS version should be 1.2 or higher" -ForegroundColor Green; Write-Host "       minTlsVersion = $minTls" -ForegroundColor Yellow } else { Write-Host "[FAIL] Minimum TLS version should be 1.2 or higher" -ForegroundColor Red; Write-Host "       minTlsVersion = $minTls" -ForegroundColor Yellow }

$authEnabled = $false
if ($authJson) { try { $authObj = $authJson | ConvertFrom-Json; if ($authObj.enabled -eq $true) { $authEnabled = $true } } catch {} }
if ($authEnabled) { Write-Host "[FAIL] Authentication/Authorization (Easy Auth) enabled" -ForegroundColor Red; Write-Host "       If your app uses its own auth (e.g., WordPress plugin), ensure it's configured securely." -ForegroundColor Yellow } else { Write-Host "[PASS] Authentication/Authorization (Easy Auth) not enabled" -ForegroundColor Green; Write-Host "       Easy Auth not enabled." -ForegroundColor Yellow }

$miPresent = $false
if ($idJson) { try { $idObj = $idJson | ConvertFrom-Json; if ($idObj.principalId) { $miPresent = $true } } catch {} }
if ($miPresent) { Write-Host "[PASS] System-assigned Managed Identity present" -ForegroundColor Green; Write-Host "       If using Key Vault references, prefer Managed Identity over app secrets." -ForegroundColor Yellow } else { Write-Host "[FAIL] System-assigned Managed Identity present" -ForegroundColor Red; Write-Host "       Managed Identity not present." -ForegroundColor Yellow }

if ($alwaysOn -eq $true) { Write-Host "[PASS] Always On should be ON for production web apps" -ForegroundColor Green; Write-Host "       alwaysOn = True" -ForegroundColor Yellow } else { Write-Host "[FAIL] Always On should be ON for production web apps" -ForegroundColor Red; Write-Host "       alwaysOn = $alwaysOn" -ForegroundColor Yellow }

# 5) App settings secret-like analysis
Write-Host "`n=== App settings secret-like analysis ===" -ForegroundColor Cyan
$appsettingsRaw = az webapp config appsettings list -g $webapp.resourceGroup -n $AppName --output json 2>$null
if ($LASTEXITCODE -ne 0 -or -not $appsettingsRaw) {
    Write-Host "[FAIL] Unable to list app settings" -ForegroundColor Red
} else {
    $settings = $appsettingsRaw | ConvertFrom-Json
    $secretPatterns = @("password","pwd","secret","key","token","connectionstring","apikey","api_key","appinsights","workspacekey","insightvm","insightvmapikey")
    $found = @()
    foreach ($s in $settings) {
        $n = $s.name.ToLower()
        foreach ($p in $secretPatterns) { if ($n -like "*$p*") { $found += $s; break } }
    }
    if ($found.Count -eq 0) {
        Write-Host "[PASS] No app settings with secret-like names" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] App settings with secret-like names found" -ForegroundColor Red
        Write-Host "       Found: " + ($found.name -join ", ") -ForegroundColor Yellow
        foreach ($s in $found) {
            Write-Host ""
            Write-Host "Key: $($s.name)"
            Write-Host "Value: $($s.value)"
            Write-Host "slotSetting: $($s.slotSetting)"
            Write-Host "Recommendation: Move this secret into Azure Key Vault and reference it from app settings using Key Vault references with a managed identity."
        }
    }
}

# 6) Connection strings check
Write-Host "`n=== Connection strings check ===" -ForegroundColor Cyan
$connRaw = az webapp config connection-string list -g $webapp.resourceGroup -n $AppName --output json 2>$null
if ($LASTEXITCODE -ne 0 -or -not $connRaw) {
    Write-Host "[FAIL] Unable to list connection strings" -ForegroundColor Red
} else {
    $cs = $connRaw | ConvertFrom-Json
    $plain = @()
    foreach ($p in $cs.PSObject.Properties) { if ($cs.$($p.Name)) { $plain += $p.Name } }
    if ($plain.Count -eq 0) {
        Write-Host "[PASS] No connection strings stored in clear app config" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Connection strings stored in clear app config" -ForegroundColor Red
        Write-Host "       Found: " + ($plain -join ", ") -ForegroundColor Yellow
    }
}

# 7) Diagnostic settings and Log Analytics
Write-Host "`n=== Diagnostic settings and Log Analytics ===" -ForegroundColor Cyan
$resourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$AppName"
$diagRaw = az monitor diagnostic-settings list --resource $resourceId --output json 2>$null
if ($LASTEXITCODE -ne 0 -or -not $diagRaw) {
    Write-Host "[FAIL] Diagnostic settings not found or cannot be retrieved" -ForegroundColor Red
} else {
    $diag = $diagRaw | ConvertFrom-Json
    $hasLA = $false
    foreach ($d in $diag) { if ($d.workspaceId) { $hasLA = $true } }
    if ($hasLA) {
        Write-Host "[PASS] Diagnostic settings sending to Log Analytics" -ForegroundColor Green
        Write-Host "       Count settings: $($diag.Count)" -ForegroundColor Yellow
    } else {
        Write-Host "[FAIL] Diagnostic settings sending to Log Analytics" -ForegroundColor Red
        Write-Host "       Count settings: $($diag.Count)" -ForegroundColor Yellow
    }
}

# 8) Defender for Cloud pricing and assessments
Write-Host "`n=== Defender for Cloud and security assessments ===" -ForegroundColor Cyan
$pricingRaw = az security pricing list --output json --only-show-errors 2>$null
$assessRaw  = az security assessment list --output json --only-show-errors 2>$null
$defender = $false
if ($pricingRaw) {
    try { $pricing = $pricingRaw | ConvertFrom-Json } catch { $pricing = $null }
    if ($pricing) {
        foreach ($p in $pricing) {
            if ($p.name -match "AppService" -or $p.name -match "App Service" -or $p.name -match "AppServices") {
                if ($p.pricingTier -and ($p.pricingTier -ne "Free")) { $defender = $true }
            }
        }
    }
}

$relevant = @()
if ($assessRaw) {
    $parsed = $null
    try { $parsed = $assessRaw | ConvertFrom-Json -AsHashtable } catch { try { $parsed = $assessRaw | ConvertFrom-Json } catch { $parsed = $null } }
    if ($parsed) {
        foreach ($a in $parsed) {
            $resId = $null
            try { $resId = $a.resourceDetails.id } catch {}
            if (-not $resId) { try { $resId = $a.resourceDetails.resourceId } catch {} }
            if (-not $resId) { try { $resId = $a.additionalData.resourceId } catch {} }
            if ($resId -and ($resId -eq $resourceId)) { $relevant += $a }
        }
    }
}

if ($defender -or $relevant.Count -gt 0) {
    Write-Host "[PASS] Microsoft Defender for Cloud plan enabled for App Service or assessments present" -ForegroundColor Green
    if ($relevant.Count -gt 0) {
        Write-Host "       Found assessments referencing this Web App: $($relevant.Count)" -ForegroundColor Yellow
        foreach ($ra in $relevant) {
            $title = $null; try { $title = $ra.displayName } catch { $title = $ra.name }
            $status = $null; try { $status = $ra.status.displayName } catch {}
            Write-Host ("  - {0} | status: {1}" -f $title, $status)
        }
    }
} else {
    Write-Host "[FAIL] Microsoft Defender for Cloud plan enabled for App Service or assessments present" -ForegroundColor Red
    Write-Host "       Check Defender pricing and recommendations in portal" -ForegroundColor Yellow
}

# 9) WAF detection (Front Door / Application Gateway) - best effort
Write-Host "`n=== WAF detection (best-effort) ===" -ForegroundColor Cyan
$fdsRaw = az network front-door list --output json 2>$null
$agRaw  = az network application-gateway list --output json 2>$null
$foundWaf = $false
if ($fdsRaw) {
    $fds = $fdsRaw | ConvertFrom-Json
    foreach ($fd in $fds) {
        if ($fd.frontendEndpoints) {
            foreach ($fe in $fd.frontendEndpoints) {
                foreach ($h in $webapp.enabledHostNames) { if ($fe.hostName -eq $h) { $foundWaf = $true; Write-Host "Front Door found referencing $h (WAF may be enabled)"; break } }
            }
        }
    }
}
if ($agRaw) {
    $ags = $agRaw | ConvertFrom-Json
    foreach ($ag in $ags) { Write-Host "Application Gateway found: $($ag.name) in resource group $($ag.resourceGroup)" }
}
if ($foundWaf) { Write-Host "[PASS] WAF fronting detected (Front Door or App Gateway)" -ForegroundColor Green } else { Write-Host "[FAIL] WAF fronting detected (Front Door or App Gateway)" -ForegroundColor Red; Write-Host "       If false, ensure traffic is fronted by WAF or App Gateway" -ForegroundColor Yellow }

# 10) App Service Plan SKU and isolation
Write-Host "`n=== App Service Plan SKU and isolation ===" -ForegroundColor Cyan
$sFarm = az webapp show -g $webapp.resourceGroup -n $AppName --query serverFarmId -o tsv 2>$null
if (-not $sFarm) {
    Write-Host "[FAIL] Unable to determine App Service Plan" -ForegroundColor Red
} else {
    $aspRaw = az resource show --ids $sFarm --output json 2>$null
    if ($aspRaw) {
        $asp = $aspRaw | ConvertFrom-Json
        $sku = $null; $tier = $null
        try { $sku = $asp.sku.name } catch {}
        try { $tier = $asp.sku.tier } catch {}
        Write-Host "SKU: $sku  Tier: $tier"
        if ($tier -match "Isolated|PremiumV2|PremiumV3") { Write-Host "[PASS] App Service Plan is in an isolated or premium tier (recommended for production)" -ForegroundColor Green } else { Write-Host "[FAIL] App Service Plan is in an isolated or premium tier (recommended for production)" -ForegroundColor Red; Write-Host "       Consider Premium/Isolated for production workloads" -ForegroundColor Yellow }
    } else {
        Write-Host "[FAIL] Unable to retrieve App Service Plan details" -ForegroundColor Red
    }
}

# 11) Deployment slots presence
Write-Host "`n=== Deployment slots presence ===" -ForegroundColor Cyan
$slotsRaw = az webapp deployment slot list -g $webapp.resourceGroup -n $AppName --output json 2>$null
if ($LASTEXITCODE -ne 0 -or -not $slotsRaw) {
    Write-Host "[FAIL] Unable to list deployment slots" -ForegroundColor Red
} else {
    $slots = $slotsRaw | ConvertFrom-Json
    Write-Host "Slots found: $($slots.Count)"
    Write-Host "[PASS] Deployment slots listed" -ForegroundColor Green
}

# 12) FTP/FTPS and SCM type check
Write-Host "`n=== FTP/FTPS and SCM type check ===" -ForegroundColor Cyan
$cfgRaw = az webapp config show -g $webapp.resourceGroup -n $AppName --query '{ftpsState:ftpsState,scmType:scmType}' --output json 2>$null
if ($cfgRaw) {
    $cfg = $cfgRaw | ConvertFrom-Json
    if ($cfg.ftpsState -eq "Disabled") { Write-Host "[PASS] FTP should be Disabled" -ForegroundColor Green; Write-Host "       ftpsState = Disabled" -ForegroundColor Yellow } else { Write-Host "[FAIL] FTP should be Disabled" -ForegroundColor Red; Write-Host "       ftpsState = $($cfg.ftpsState)" -ForegroundColor Yellow }
    if ($cfg.scmType -ne "LocalGit") { Write-Host "[PASS] Local Git should not be enabled unless required" -ForegroundColor Green; Write-Host "       scmType = $($cfg.scmType)" -ForegroundColor Yellow } else { Write-Host "[FAIL] Local Git should not be enabled unless required" -ForegroundColor Red; Write-Host "       scmType = LocalGit" -ForegroundColor Yellow }
} else {
    Write-Host "[FAIL] Unable to retrieve ftps/scm config" -ForegroundColor Red
}

# 13) Container port mapping (WEBSITES_PORT)
Write-Host "`n=== Container port mapping (WEBSITES_PORT) for Linux containers ===" -ForegroundColor Cyan
$containerCfgRaw = az webapp config container show -g $webapp.resourceGroup -n $AppName --output json 2>$null
$wsPort = $null
if ($containerCfgRaw) {
    try {
        $appsettingsObj = $appsettingsRaw | ConvertFrom-Json
        $wsPort = ($appsettingsObj | Where-Object { $_.name -eq "WEBSITES_PORT" }).value
    } catch {}
}
if ($wsPort) { Write-Host "[PASS] Container port (WEBSITES_PORT) should be set for Linux containers" -ForegroundColor Green; Write-Host "       WEBSITES_PORT = $wsPort" -ForegroundColor Yellow } else { Write-Host "[FAIL] Container port (WEBSITES_PORT) should be set for Linux containers" -ForegroundColor Red; Write-Host "       WEBSITES_PORT not set" -ForegroundColor Yellow }

# 14) Azure Database for MySQL checks (optional)
Write-Host "`n=== Azure Database for MySQL checks (optional) ===" -ForegroundColor Cyan
if (-not $MySqlServer) {
    Write-Host "Skipping MySQL checks (no MySqlServer parameter)"
} else {
    $mysqlRaw = az mysql server show -g $MySqlRg -n $MySqlServer --output json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $mysqlRaw) {
        Write-Host "[FAIL] Unable to retrieve MySQL server" -ForegroundColor Red
    } else {
        $mysql = $mysqlRaw | ConvertFrom-Json
        Write-Host "MySQL server name: $($mysql.name)"
        if ($mysql.publicNetworkAccess -eq "Disabled") { Write-Host "[PASS] MySQL publicNetworkAccess disabled" -ForegroundColor Green; Write-Host "       publicNetworkAccess = Disabled" -ForegroundColor Yellow } else { Write-Host "[FAIL] MySQL publicNetworkAccess disabled" -ForegroundColor Red; Write-Host "       publicNetworkAccess = $($mysql.publicNetworkAccess)" -ForegroundColor Yellow }
        if ($mysql.sslEnforcement -eq "Enabled") { Write-Host "[PASS] MySQL SSL enforcement enabled" -ForegroundColor Green; Write-Host "       sslEnforcement = Enabled" -ForegroundColor Yellow } else { Write-Host "[FAIL] MySQL SSL enforcement enabled" -ForegroundColor Red; Write-Host "       sslEnforcement = $($mysql.sslEnforcement)" -ForegroundColor Yellow }
        $fwRaw = az mysql server firewall-rule list -g $MySqlRg -s $MySqlServer --output json 2>$null
        if ($fwRaw) { $fw = $fwRaw | ConvertFrom-Json; Write-Host "MySQL firewall rules count: $($fw.Count)"; if ($fw.Count -gt 0) { Write-Host "[PASS] MySQL firewall rules restrict access" -ForegroundColor Green } else { Write-Host "[FAIL] MySQL firewall rules restrict access" -ForegroundColor Red } }
        $q = "[?contains(properties.privateLinkServiceConnections[].properties.privateLinkServiceId, '$MySqlServer')]"
        $peRaw = az network private-endpoint list --query $q --output json 2>$null
        $pe = $null; if ($peRaw) { $pe = $peRaw | ConvertFrom-Json }
        if ($pe -and $pe.Count -gt 0) { Write-Host "[PASS] MySQL has Private Endpoint" -ForegroundColor Green; Write-Host "       Private endpoint count: $($pe.Count)" -ForegroundColor Yellow } else { Write-Host "[FAIL] MySQL has Private Endpoint" -ForegroundColor Red; Write-Host "       No private endpoint found" -ForegroundColor Yellow }
    }
}

# 15) ACR image manifest checks (optional)
Write-Host "`n=== ACR image manifest checks (optional) ===" -ForegroundColor Cyan
if (-not $AcrName) {
    Write-Host "Skipping ACR checks (no AcrName parameter)"
} else {
    $containerJson = az webapp config container show -g $webapp.resourceGroup -n $AppName --output json 2>$null
    $imageRef = $null
    if ($containerJson) { $c = $containerJson | ConvertFrom-Json; if ($c.imageName) { $imageRef = $c.imageName } }
    if (-not $imageRef -and $appsettingsRaw) {
        try { $appsettingsObj = $appsettingsRaw | ConvertFrom-Json; $candidate = $appsettingsObj | Where-Object { $_.name -match "DOCKER|IMAGE|WEBSITE_CONTAINER_IMAGE" }; if ($candidate) { $imageRef = $candidate.value } } catch {}
    }
    if (-not $imageRef) {
        Write-Host "No container image reference found in app config or app settings. Skipping ACR manifest checks."
    } else {
        Write-Host "Container image reference found: $imageRef"
        $repo = $null; $tag = "latest"
        if ($imageRef -match "/") {
            $parts = $imageRef.Split("/")
            $last = $parts[-1]
            if ($last -match ":") { $repo = ($last.Split(":"))[0]; $tag = ($last.Split(":"))[1] } else { $repo = $last }
        }
        $manifestsRaw = az acr repository show-manifests -n $AcrName --repository $repo --output json 2>$null
        if ($manifestsRaw) {
            $manifests = $manifestsRaw | ConvertFrom-Json
            $latest = $manifests | Where-Object { $_.tags -contains $tag } | Select-Object -First 1
            if ($latest) { Write-Host "Image manifest digest: $($latest.digest)"; Write-Host "[PASS] Image pinned by digest" -ForegroundColor Green } else { Write-Host "[FAIL] Image manifest for tag found" -ForegroundColor Red; Write-Host "       Tag $tag not found in ACR repository $repo" -ForegroundColor Yellow }
        } else {
            Write-Host "[FAIL] No manifests returned or insufficient permissions to query ACR." -ForegroundColor Red
        }
    }
}

# 16) Key Vault checks (optional)
Write-Host "`n=== Key Vault access checks (optional) ===" -ForegroundColor Cyan
if (-not $VaultName) {
    Write-Host "Skipping Key Vault checks (no VaultName parameter)"
} else {
    $kvRaw = az keyvault show -n $VaultName --output json 2>$null
    if (-not $kvRaw) {
        Write-Host "[FAIL] Key Vault not found or insufficient permissions" -ForegroundColor Red
    } else {
        $kv = $kvRaw | ConvertFrom-Json
        Write-Host "Key Vault found: $($kv.name)"
        $kvScope = "/subscriptions/$SubscriptionId/resourceGroups/$($kv.resourceGroup)/providers/Microsoft.KeyVault/vaults/$VaultName"
        $assignsRaw = az role assignment list --scope $kvScope --output json 2>$null
        if ($assignsRaw) {
            $assigns = $assignsRaw | ConvertFrom-Json
            $miId = $null
            try { $miId = (az webapp identity show -g $webapp.resourceGroup -n $AppName --output json 2>$null | ConvertFrom-Json).principalId } catch {}
            $hasMi = $assigns | Where-Object { $_.principalId -eq $miId }
            if ($hasMi) { Write-Host "[PASS] App managed identity has Key Vault access" -ForegroundColor Green } else { Write-Host "[FAIL] App managed identity has Key Vault access" -ForegroundColor Red; Write-Host "       If false, grant GET secret permission to the app's managed identity" -ForegroundColor Yellow }
        } else {
            Write-Host "Unable to list role assignments for Key Vault or none present."
        }
    }
}

#17)  Role assignments for the Web App resource (detailed reporting) ===
$scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$AppName"

# Retrieve role assignments (raw JSON)
$raRaw = az role assignment list --scope $scope --output json 2>$null

if (-not $raRaw) {
    Write-Host "`n=== Role assignments for the Web App resource ===" -ForegroundColor Cyan
    Write-Host "[FAIL] No role assignments found or unable to list" -ForegroundColor Red
    return
}

# Parse JSON
$ra = $raRaw | ConvertFrom-Json

Write-Host "`n=== Role assignments for the Web App resource ===" -ForegroundColor Cyan

# 1) Summary count
$total = $ra.Count
Write-Host "Total role assignments for scope $scope : $total"

# 2) Compact table of assignments (principalType, principalName, principalId, role)
Write-Host "`nRole assignments (principalType, principalName, principalId, roleDefinitionName):"
$ra | Select-Object principalType, principalName, principalId, roleDefinitionName | Format-Table -AutoSize

# 3) Group by roleDefinitionName with counts
Write-Host "`nRole counts (grouped by roleDefinitionName):"
$ra | Group-Object roleDefinitionName | Select-Object @{Name='Role';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}} | Sort-Object -Property Count -Descending | Format-Table -AutoSize

# 4) Top 20 assignments (if list is long)
Write-Host "`nTop 20 role assignments (principalName, principalId, roleDefinitionName):"
$ra | Select-Object principalName, principalId, roleDefinitionName | Select-Object -First 20 | Format-Table -AutoSize

# 5) High-privilege principals (Owner / Contributor)
Write-Host "`nHigh-privilege principals (Owner or Contributor):"
$high = $ra | Where-Object { $_.roleDefinitionName -in @('Owner','Contributor') }
if ($high -and $high.Count -gt 0) {
    $high | Select-Object principalType, principalName, principalId, roleDefinitionName | Format-Table -AutoSize
} else {
    Write-Host "  (none found)" -ForegroundColor Yellow
}

# 6) Breakdown by principalType (User, ServicePrincipal, ManagedIdentity, Group)
Write-Host "`nAssignments by principalType:"
$ra | Group-Object principalType | Select-Object @{Name='PrincipalType';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}} | Format-Table -AutoSize

# 7) Optional: show assignments for a specific principal (uncomment and set $filterPrincipal)
# $filterPrincipal = "name@domain.com"   # example
# $ra | Where-Object { $_.principalName -eq $filterPrincipal } | Select-Object principalType, principalName, principalId, roleDefinitionName | Format-Table -AutoSize

Write-Host "`n[PASS] Role assignments listed; review for least privilege" -ForegroundColor Green

# 18) Optional Kudu probe (uses publishing credentials)
Write-Host "`n=== Optional Kudu API probe (uses publishing credentials) ===" -ForegroundColor Cyan
if (-not $RunKuduProbe) {
    Write-Host "Skipping Kudu probe (RunKuduProbe not set)"
} else {
    $credsRaw = az webapp deployment list-publishing-credentials -g $webapp.resourceGroup -n $AppName --output json 2>$null
    if (-not $credsRaw) {
        Write-Host "[FAIL] Publishing credentials not available; cannot run Kudu probe" -ForegroundColor Red
    } else {
        $creds = $credsRaw | ConvertFrom-Json
        $user = $creds.publishingUserName; $pass = $creds.publishingPassword
        $kuduUrl = "https://$AppName.scm.azurewebsites.net/api/settings"
        try {
            $pair = "$user`:$pass"
            $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
            $resp = Invoke-RestMethod -Uri $kuduUrl -Headers @{ Authorization = "Basic $auth" } -Method Get -ErrorAction Stop
            Write-Host "[PASS] Kudu /api/settings accessible with publishing credentials" -ForegroundColor Green
        } catch {
            Write-Host "[FAIL] Kudu /api/settings probe failed or credentials invalid" -ForegroundColor Red
        }
    }
}

# Final summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Inspection complete for $AppName in $ResourceGroup (subscription $SubscriptionId)."
Write-Host "If any [FAIL] items appeared above, re-run the specific az command shown in the relevant section to get raw JSON and investigate further."