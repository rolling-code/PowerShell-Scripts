#requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:EngineVersion = '2.1.0'
$script:Catalog = $null
$script:CacheDirectory = $null
$script:TimeoutSeconds = 20

$script:ManagedProfiles = @(
    [pscustomobject]@{ Name='Kinsta'; ServiceType='Managed WordPress'; CNameSuffixes=@('kinsta.cloud','kinstacdn.com'); NsSuffixes=@(); HeaderNames=@('X-Kinsta-Cache','X-Kinsta-Edge','Ki-Cache-Type'); HostSuffixes=@() },
    [pscustomobject]@{ Name='WordPress.com'; ServiceType='Managed WordPress'; CNameSuffixes=@('wordpress.com'); NsSuffixes=@('wordpress.com'); HeaderNames=@('X-ac','X-hacker'); HostSuffixes=@('wordpress.com') },
    [pscustomobject]@{ Name='WordPress VIP'; ServiceType='Managed WordPress'; CNameSuffixes=@('wpcomvip.com','go-vip.net'); NsSuffixes=@(); HeaderNames=@('X-ac','X-hacker'); HostSuffixes=@() },
    [pscustomobject]@{ Name='WP Engine'; ServiceType='Managed WordPress'; CNameSuffixes=@('wpenginepowered.com'); NsSuffixes=@(); HeaderNames=@('X-WPE','X-Cacheable'); HostSuffixes=@() },
    [pscustomobject]@{ Name='Pantheon'; ServiceType='Managed Web Platform'; CNameSuffixes=@('pantheonsite.io'); NsSuffixes=@(); HeaderNames=@('X-Pantheon-Styx-Hostname'); HostSuffixes=@(); ServerPatterns=@('(?i)^Pantheon$') },
    [pscustomobject]@{ Name='Pressable'; ServiceType='Managed WordPress'; CNameSuffixes=@('pressable.com'); NsSuffixes=@(); HeaderNames=@('X-Pressable-Info'); HostSuffixes=@() },
    [pscustomobject]@{ Name='Flywheel'; ServiceType='Managed WordPress'; CNameSuffixes=@('getflywheel.com','flywheelsites.com'); NsSuffixes=@(); HeaderNames=@('X-FW-Server'); HostSuffixes=@() },
    [pscustomobject]@{ Name='Shopify'; ServiceType='Managed Commerce SaaS'; CNameSuffixes=@('myshopify.com'); NsSuffixes=@(); HeaderNames=@('X-ShopId','X-Shopify-Stage'); HostSuffixes=@('myshopify.com') },
    [pscustomobject]@{ Name='Wix'; ServiceType='Managed Website SaaS'; CNameSuffixes=@('wixdns.net','wixsite.com'); NsSuffixes=@(); HeaderNames=@('X-Wix-Request-Id','X-Wix-Published-Version'); HostSuffixes=@('wixsite.com') },
    [pscustomobject]@{ Name='Squarespace'; ServiceType='Managed Website SaaS'; CNameSuffixes=@('squarespacedns.com','squarespace.com'); NsSuffixes=@(); HeaderNames=@('X-ContextId'); HostSuffixes=@('squarespace.com') },
    [pscustomobject]@{ Name='Webflow'; ServiceType='Managed Website SaaS'; CNameSuffixes=@('proxy-ssl.webflow.com','webflow.io'); NsSuffixes=@(); HeaderNames=@('X-Webflow-Cache'); HostSuffixes=@('webflow.io') },
    [pscustomobject]@{ Name='Vercel'; ServiceType='Managed Application Platform'; CNameSuffixes=@('vercel-dns.com','vercel.app'); NsSuffixes=@(); HeaderNames=@('X-Vercel-Id','X-Vercel-Cache'); HostSuffixes=@('vercel.app') },
    [pscustomobject]@{ Name='Netlify'; ServiceType='Managed Application Platform'; CNameSuffixes=@('netlify.app','netlifyglobalcdn.com'); NsSuffixes=@(); HeaderNames=@('X-Nf-Request-Id'); HostSuffixes=@('netlify.app') },
    [pscustomobject]@{ Name='Firebase Hosting'; ServiceType='Managed Application Platform'; CNameSuffixes=@('firebaseapp.com','web.app'); NsSuffixes=@(); HeaderNames=@(); HostSuffixes=@('firebaseapp.com','web.app') },
    [pscustomobject]@{ Name='GitHub Pages'; ServiceType='Managed Static Hosting'; CNameSuffixes=@('github.io'); NsSuffixes=@(); HeaderNames=@('X-GitHub-Request-Id'); HostSuffixes=@('github.io') },
    [pscustomobject]@{ Name='Cloudflare Pages'; ServiceType='Managed Static Hosting'; CNameSuffixes=@('pages.dev'); NsSuffixes=@(); HeaderNames=@(); HostSuffixes=@('pages.dev') },
    [pscustomobject]@{ Name='Azure App Service'; ServiceType='Managed PaaS'; CNameSuffixes=@('azurewebsites.net'); NsSuffixes=@(); HeaderNames=@('X-Azure-Ref'); HostSuffixes=@('azurewebsites.net') },
    [pscustomobject]@{ Name='AWS Amplify'; ServiceType='Managed Application Platform'; CNameSuffixes=@('amplifyapp.com'); NsSuffixes=@(); HeaderNames=@(); HostSuffixes=@('amplifyapp.com') },
    [pscustomobject]@{ Name='Cloudways'; ServiceType='Managed Cloud Hosting'; CNameSuffixes=@('cloudwaysapps.com'); NsSuffixes=@(); HeaderNames=@(); HostSuffixes=@('cloudwaysapps.com') },
    [pscustomobject]@{ Name='Combell'; ServiceType='Managed Web Hosting'; CNameSuffixes=@('combell.net','combell.com','webbuilder-online.com'); NsSuffixes=@('combell.net'); HeaderNames=@(); HostSuffixes=@() },
    [pscustomobject]@{ Name='OpenSRS / Tucows'; ServiceType='Managed Email or Web Service'; CNameSuffixes=@('hostedemail.com','emailhome.com'); NsSuffixes=@(); HeaderNames=@(); HostSuffixes=@() },
    [pscustomobject]@{ Name='Newfold Digital'; ServiceType='Shared or Managed Hosting'; CNameSuffixes=@('eigbox.net','bluehost.com','netfirms.com'); NsSuffixes=@('netfirms.com','bluehost.com'); HeaderNames=@(); HostSuffixes=@() },
    [pscustomobject]@{ Name='GreenGeeks'; ServiceType='Managed Web Hosting'; CNameSuffixes=@('greengeeks.net'); NsSuffixes=@(); HeaderNames=@(); HostSuffixes=@() },
    [pscustomobject]@{ Name='GoDaddy Managed WordPress'; ServiceType='Managed WordPress'; CNameSuffixes=@('secureserver.net'); NsSuffixes=@(); HeaderNames=@('X-GD-Cache'); HostSuffixes=@() }
)

function Write-AttributionStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Message,[ValidateSet('Info','Step','Success','Warning','Error')][string]$Level='Info')
    $prefix=@{ Info='[*]'; Step='[>]'; Success='[+]'; Warning='[!]'; Error='[-]' }[$Level]
    $color=@{ Info='Cyan'; Step='Blue'; Success='Green'; Warning='Yellow'; Error='Red' }[$Level]
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Get-SafeProperty {
    param([AllowNull()]$Object,[Parameter(Mandatory=$true)][string]$Name)
    if ($null -eq $Object){ return $null }
    $property=$Object.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    if ($property){ return $property.Value }
    return $null
}

function Get-ExplicitAssetManagement {
    [CmdletBinding()]
    param([AllowNull()]$InputObject)
    $unknown=[pscustomobject]@{ Found=$false; Status='Unknown'; PatchResponsibility='Unknown'; Source='No explicit field'; Evidence='No recognized management field was supplied.'; Confidence='Low' }
    if ($null -eq $InputObject){ return $unknown }
    foreach ($name in @('Organization Managed','Managed by Organization','Is Organization Managed','IsOrganizationManaged','Is Managed','IsManaged','Managed','Management Status','Asset Management Status','Operational Scope','Operational Responsibility','Ownership Status','In Scope','Scope Status','Managed By','ManagedBy')){
        $value=Get-SafeProperty $InputObject $name
        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)){ continue }
        $raw=([string]$value).Trim(); $normalized=$raw.ToLowerInvariant()
        if ($normalized -match '^(unknown|unsure|undetermined|n/a|na|not available|not known|tbd|pending)$'){
            Write-AttributionStatus "Explicit field '$name' is '$raw'; continuing with dynamic provider attribution." Info
            return $unknown
        }
        if ($normalized -match '^(true|yes|y|1|managed|organization managed|managed by organization|in scope|internal|customer managed|self managed)$'){
            return [pscustomobject]@{ Found=$true; Status='Explicit Organization Managed'; PatchResponsibility='Yes'; Source=$name; Evidence="$name='$raw'"; Confidence='High' }
        }
        if ($normalized -match '^(false|no|n|0|unmanaged|not managed|not managed by organization|out of scope|external|provider managed|vendor managed|third[- ]party managed)$'){
            return [pscustomobject]@{ Found=$true; Status='Explicit Provider/Third-Party Managed'; PatchResponsibility='No'; Source=$name; Evidence="$name='$raw'"; Confidence='High' }
        }
        Write-AttributionStatus "Explicit field '$name' contains unrecognized value '$raw'; continuing with dynamic provider attribution." Warning
        return $unknown
    }
    return $unknown
}

function Get-CachePath {
    param([string]$Name,[string]$Extension='.dat')
    $safe=$Name -replace '[^a-zA-Z0-9._-]','_'
    return Join-Path $script:CacheDirectory ($safe+$Extension)
}

function Get-RemoteFile {
    param([string]$Name,[string]$Uri,[string]$Extension,[int]$MaximumAgeHours,[switch]$ForceRefresh)
    $path=Get-CachePath $Name $Extension
    $fresh=(Test-Path -LiteralPath $path -PathType Leaf) -and (([datetime]::UtcNow-(Get-Item $path).LastWriteTimeUtc).TotalHours -le $MaximumAgeHours)
    if ($fresh -and -not $ForceRefresh){ Write-AttributionStatus "$Name cache is current: $path" Success; return $path }
    Write-AttributionStatus "Looking up $Name..." Step
    Write-AttributionStatus "Source: $Uri" Info
    $temporary=$path+'.download'
    try{
        $parameters=@{ Uri=$Uri; OutFile=$temporary; TimeoutSec=120; ErrorAction='Stop'; Headers=@{'User-Agent'="AssetAttributionEngine/$script:EngineVersion"} }
        if ($PSVersionTable.PSVersion.Major -le 5){ $parameters.UseBasicParsing=$true }
        Invoke-WebRequest @parameters
        if (-not (Test-Path $temporary) -or (Get-Item $temporary).Length -eq 0){ throw 'Downloaded file is empty.' }
        Move-Item -LiteralPath $temporary -Destination $path -Force
        Write-AttributionStatus "$Name loaded: $((Get-Item $path).Length) bytes." Success
        return $path
    }catch{
        Remove-Item $temporary -Force -ErrorAction SilentlyContinue
        if (Test-Path $path){ Write-AttributionStatus "$Name refresh failed; using stale cache. $($_.Exception.Message)" Warning; return $path }
        Write-AttributionStatus "$Name unavailable: $($_.Exception.Message)" Warning
        return $null
    }
}

function Import-JsonFile {
    param([string]$Path)
    if (-not $Path){ return $null }
    $bytes=[IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B){
        $extract=Join-Path $script:CacheDirectory ('extract-'+[guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $extract -Force | Out-Null
        try{
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            [IO.Compression.ZipFile]::ExtractToDirectory($Path,$extract)
            $json=Get-ChildItem $extract -Filter *.json -Recurse | Select-Object -First 1
            if (-not $json){ throw 'ZIP archive did not contain JSON.' }
            return Get-Content $json.FullName -Raw | ConvertFrom-Json
        }finally{ Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue }
    }
    return Get-Content $Path -Raw | ConvertFrom-Json
}

function Add-Range {
    param([Collections.Generic.List[object]]$List,[string]$Provider,[string]$ServiceType,[string]$Responsibility,[string]$Cidr,[string]$Source)
    if ([string]::IsNullOrWhiteSpace($Cidr) -or $Cidr -notmatch '/'){ return }
    $List.Add([pscustomobject]@{ Provider=$Provider; ServiceType=$ServiceType; Responsibility=$Responsibility; Cidr=$Cidr.Trim(); Source=$Source }) | Out-Null
}

function Initialize-AssetAttributionEngine {
    [CmdletBinding()]
    param([string]$CacheDirectory=(Join-Path $env:LOCALAPPDATA 'AssetAttributionEngine'),[int]$CacheMaximumAgeHours=24,[int]$TimeoutSeconds=20,[switch]$ForceRefresh)
    $script:CacheDirectory=$CacheDirectory; $script:TimeoutSeconds=$TimeoutSeconds
    New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null
    Write-Host ''
    Write-AttributionStatus "Initializing multi-signal provider attribution engine v$script:EngineVersion" Step
    Write-AttributionStatus 'Priority: recognized explicit CSV value, dynamic provider attribution, then Unknown.' Info
    Write-AttributionStatus 'Unknown or unrecognized CSV values do not suppress dynamic attribution.' Info
    Write-AttributionStatus 'Cloudflare is evaluated separately from management and patch responsibility.' Info
    $ranges=New-Object 'System.Collections.Generic.List[object]'
    $sourceCounts=[ordered]@{}

    $path=Get-RemoteFile 'Cloudflare IPv4 ranges' 'https://www.cloudflare.com/ips-v4/' '.txt' $CacheMaximumAgeHours -ForceRefresh:$ForceRefresh
    $countBefore=$ranges.Count; if ($path){ foreach ($line in Get-Content $path){ Add-Range $ranges 'Cloudflare' 'CDN/WAF' 'Separate' $line 'Official Cloudflare IPv4 feed' } }; $sourceCounts.CloudflareIPv4=$ranges.Count-$countBefore
    $path=Get-RemoteFile 'Cloudflare IPv6 ranges' 'https://www.cloudflare.com/ips-v6/' '.txt' $CacheMaximumAgeHours -ForceRefresh:$ForceRefresh
    $countBefore=$ranges.Count; if ($path){ foreach ($line in Get-Content $path){ Add-Range $ranges 'Cloudflare' 'CDN/WAF' 'Separate' $line 'Official Cloudflare IPv6 feed' } }; $sourceCounts.CloudflareIPv6=$ranges.Count-$countBefore

    $path=Get-RemoteFile 'AWS IP ranges' 'https://ip-ranges.amazonaws.com/ip-ranges.json' '.json' $CacheMaximumAgeHours -ForceRefresh:$ForceRefresh
    $countBefore=$ranges.Count; if ($path){ try{$doc=Import-JsonFile $path; foreach ($p in @($doc.prefixes)){Add-Range $ranges 'Amazon Web Services' ("Cloud/IaaS $([string](Get-SafeProperty $p 'service'))") 'Customer' ([string](Get-SafeProperty $p 'ip_prefix')) 'Official AWS feed'};foreach ($p in @($doc.ipv6_prefixes)){Add-Range $ranges 'Amazon Web Services' ("Cloud/IaaS $([string](Get-SafeProperty $p 'service'))") 'Customer' ([string](Get-SafeProperty $p 'ipv6_prefix')) 'Official AWS feed'}}catch{Write-AttributionStatus "AWS parsing failed: $($_.Exception.Message)" Warning} }; $sourceCounts.AWS=$ranges.Count-$countBefore

    $path=Get-RemoteFile 'Google Cloud ranges' 'https://www.gstatic.com/ipranges/cloud.json' '.json' $CacheMaximumAgeHours -ForceRefresh:$ForceRefresh
    $countBefore=$ranges.Count; if ($path){ try{$doc=Import-JsonFile $path;foreach ($p in @($doc.prefixes)){$v4=[string](Get-SafeProperty $p 'ipv4Prefix');$v6=[string](Get-SafeProperty $p 'ipv6Prefix');$cidr=if ($v4){$v4}else{$v6};Add-Range $ranges 'Google Cloud' ("Cloud/IaaS $([string](Get-SafeProperty $p 'service'))") 'Customer' $cidr 'Official Google Cloud feed'}}catch{Write-AttributionStatus "Google Cloud parsing failed: $($_.Exception.Message)" Warning} }; $sourceCounts.GoogleCloud=$ranges.Count-$countBefore

    $path=Get-RemoteFile 'Oracle Cloud ranges' 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json' '.json' $CacheMaximumAgeHours -ForceRefresh:$ForceRefresh
    $countBefore=$ranges.Count; if ($path){try{$doc=Import-JsonFile $path;foreach ($region in @($doc.regions)){foreach ($item in @($region.cidrs)){Add-Range $ranges 'Oracle Cloud' ("Cloud/IaaS $([string](Get-SafeProperty $item 'tags'))") 'Customer' ([string](Get-SafeProperty $item 'cidr')) 'Official Oracle Cloud feed'}}}catch{Write-AttributionStatus "Oracle Cloud parsing failed: $($_.Exception.Message)" Warning}}; $sourceCounts.OracleCloud=$ranges.Count-$countBefore

    $path=Get-RemoteFile 'DigitalOcean IP ranges' 'https://digitalocean.com/geo/google.csv' '.csv' $CacheMaximumAgeHours -ForceRefresh:$ForceRefresh
    $countBefore=$ranges.Count; if ($path){foreach ($line in Get-Content $path){if ($line -match '^(?<cidr>[^,]+),'){Add-Range $ranges 'DigitalOcean' 'Cloud/IaaS' 'Customer' $Matches.cidr 'Official DigitalOcean feed'}}}; $sourceCounts.DigitalOcean=$ranges.Count-$countBefore

    $path=Get-RemoteFile 'Fastly IP ranges' 'https://api.fastly.com/public-ip-list' '.json' $CacheMaximumAgeHours -ForceRefresh:$ForceRefresh
    $countBefore=$ranges.Count; if ($path){try{$doc=Import-JsonFile $path;foreach ($cidr in @($doc.addresses)+@($doc.ipv6_addresses)){Add-Range $ranges 'Fastly' 'CDN' 'Separate' ([string]$cidr) 'Official Fastly feed'}}catch{Write-AttributionStatus "Fastly parsing failed: $($_.Exception.Message)" Warning}}; $sourceCounts.Fastly=$ranges.Count-$countBefore

    $path=Get-RemoteFile 'WordPress VIP ranges' 'https://go-vip.net/ip-ranges.json' '.json' $CacheMaximumAgeHours -ForceRefresh:$ForceRefresh
    $countBefore=$ranges.Count; if ($path){try{$doc=Import-JsonFile $path;foreach ($property in $doc.PSObject.Properties){foreach ($value in @($property.Value)){if ([string]$value -match '/'){Add-Range $ranges 'WordPress VIP' 'Managed WordPress' 'Provider' ([string]$value) 'Official WordPress VIP feed'}}}}catch{Write-AttributionStatus "WordPress VIP parsing failed: $($_.Exception.Message)" Warning}}; $sourceCounts.WordPressVIP=$ranges.Count-$countBefore

    $confirmation=Get-RemoteFile 'Azure service-tag download page' 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519' '.html' $CacheMaximumAgeHours -ForceRefresh:$ForceRefresh
    $sourceCounts.Azure=0
    if ($confirmation){
        $html=Get-Content $confirmation -Raw
        $match=[regex]::Match($html,'https://download\.microsoft\.com/download/[^"'']+ServiceTags_Public_[0-9]+\.json')
        if ($match.Success){
            $path=Get-RemoteFile 'Azure service-tag ranges' $match.Value '.json' $CacheMaximumAgeHours -ForceRefresh:$ForceRefresh
            $countBefore=$ranges.Count
            if ($path){try{$doc=Import-JsonFile $path;foreach ($value in @($doc.values)){$properties=Get-SafeProperty $value 'properties';foreach ($cidr in @(Get-SafeProperty $properties 'addressPrefixes')){Add-Range $ranges 'Microsoft Azure' ("Azure network range $([string](Get-SafeProperty $properties 'systemService'))") 'Unknown' ([string]$cidr) 'Official Azure service tags'}}}catch{Write-AttributionStatus "Azure parsing failed: $($_.Exception.Message)" Warning}}
            $sourceCounts.Azure=$ranges.Count-$countBefore
        }else{ Write-AttributionStatus 'Azure service-tag JSON URL not found on Microsoft confirmation page.' Warning }
    }

    foreach ($entry in $sourceCounts.GetEnumerator()){ Write-AttributionStatus "$($entry.Key): $($entry.Value) ranges loaded." $(if ($entry.Value -gt 0){'Success'}else{'Warning'}) }
    $script:Catalog=[pscustomobject]@{ Version=$script:EngineVersion; RetrievedUtc=[datetime]::UtcNow.ToString('o'); Ranges=$ranges.ToArray(); Profiles=$script:ManagedProfiles; SourceCounts=[pscustomobject]$sourceCounts }
    Write-AttributionStatus "Dynamic range catalog ready: $($ranges.Count) CIDR entries." Success
    Write-AttributionStatus "Managed-platform fingerprint profiles: $($script:ManagedProfiles.Count)." Success
    Write-AttributionStatus 'Generic AWS, Google Cloud, Oracle Cloud, and DigitalOcean matches are treated as likely customer-managed infrastructure. Azure service-tag matches identify Microsoft network space only; Azure ownership and patch responsibility remain unknown without stronger platform evidence.' Info
    Write-Host ''
    return $script:Catalog
}

function Test-IpInCidr {
    param([string]$IpAddress,[string]$Cidr)
    try{$parts=$Cidr.Split('/');if ($parts.Count -ne 2){return $false};$ip=[Net.IPAddress]::Parse($IpAddress);$net=[Net.IPAddress]::Parse($parts[0]);$bits=[int]$parts[1];$a=$ip.GetAddressBytes();$n=$net.GetAddressBytes();if ($a.Length -ne $n.Length){return $false};$full=[math]::Floor($bits/8);$rem=$bits%8;for($i=0;$i -lt $full;$i++){if ($a[$i] -ne $n[$i]){return $false}};if ($rem -gt 0){$mask=(0xFF -shl (8-$rem)) -band 0xFF;if (($a[$full] -band $mask) -ne ($n[$full] -band $mask)){return $false}};return $true}catch{return $false}
}

function Get-DnsEvidence {
    param([string]$HostName)
    $addresses=New-Object 'System.Collections.Generic.List[string]'
    $cnames=New-Object 'System.Collections.Generic.List[string]'
    $nameservers=New-Object 'System.Collections.Generic.List[string]'
    $reverseDns=New-Object 'System.Collections.Generic.List[string]'
    $parsedIp=$null
    if ([Net.IPAddress]::TryParse($HostName,[ref]$parsedIp)) {
        $addresses.Add($parsedIp.IPAddressToString)|Out-Null
    } elseif (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        foreach ($type in @('A','AAAA')) {
            try { foreach ($r in @(Resolve-DnsName $HostName -Type $type -DnsOnly -ErrorAction Stop)) { if ($r.IPAddress) {$addresses.Add([string]$r.IPAddress)|Out-Null}; if ($r.NameHost) {$cnames.Add(([string]$r.NameHost).TrimEnd('.').ToLowerInvariant())|Out-Null} } } catch {}
        }
        try { foreach ($r in @(Resolve-DnsName $HostName -Type CNAME -DnsOnly -ErrorAction Stop)) { if ($r.NameHost) {$cnames.Add(([string]$r.NameHost).TrimEnd('.').ToLowerInvariant())|Out-Null} } } catch {}
        $labels=@($HostName.Trim('.').Split('.')); $parent=if($labels.Count -ge 2){($labels[($labels.Count-2)..($labels.Count-1)] -join '.')}else{$HostName}
        try { foreach ($r in @(Resolve-DnsName $parent -Type NS -DnsOnly -ErrorAction Stop)) { if ($r.NameHost) {$nameservers.Add(([string]$r.NameHost).TrimEnd('.').ToLowerInvariant())|Out-Null} } } catch {}
    }
    foreach ($address in @($addresses|Sort-Object -Unique)) { try {$ptr=[Net.Dns]::GetHostEntry($address).HostName;if($ptr){$reverseDns.Add($ptr.TrimEnd('.').ToLowerInvariant())|Out-Null}}catch{} }
    return [pscustomobject]@{Addresses=@($addresses|Sort-Object -Unique);CNames=@($cnames|Sort-Object -Unique);NameServers=@($nameservers|Sort-Object -Unique);ReverseDns=@($reverseDns|Sort-Object -Unique)}
}

function Test-Suffix { param([string]$Value,[string[]]$Suffixes) foreach ($suffix in $Suffixes){$s=$suffix.TrimStart('.').ToLowerInvariant();$v=$Value.ToLowerInvariant();if ($v -eq $s -or $v.EndsWith('.'+$s)){return $true}};return $false }

function Get-AssetProviderAttribution {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Target,[AllowNull()]$InputMetadata,[AllowNull()]$Headers,[AllowNull()][string]$EffectiveUrl,[AllowNull()][string]$RedirectDestination,[AllowNull()][string]$Content,[bool]$CloudflareDetected=$false,[AllowNull()][string]$CloudflareIndicators)
    if ($null -eq $script:Catalog){Initialize-AssetAttributionEngine|Out-Null}
    $uri=if ($Target -match '^(?i)https?://'){[uri]$Target}else{[uri]("https://"+$Target.Trim('/'))}
    $hostName=$uri.Host.ToLowerInvariant();$dns=Get-DnsEvidence $hostName;$explicit=Get-ExplicitAssetManagement $InputMetadata
    $effectiveHost=$hostName;if ($EffectiveUrl){try{$effectiveHost=([uri]$EffectiveUrl).Host.ToLowerInvariant()}catch{}}
    $azureIndicators=New-Object 'System.Collections.Generic.List[string]'
    $azureSupportingIndicators=New-Object 'System.Collections.Generic.List[string]'
    $azureArrAffinity=$false;$azureArrAffinitySameSite=$false;$azureWebsitesHost=$false;$azureStrongHeader=$false
    if(Test-Suffix $effectiveHost @('azurewebsites.net')){$azureWebsitesHost=$true;$azureIndicators.Add("effective host $effectiveHost")|Out-Null}
    if(-not [string]::IsNullOrWhiteSpace($RedirectDestination)){try{$azureRedirectHost=([uri]$RedirectDestination).Host.ToLowerInvariant();if(Test-Suffix $azureRedirectHost @('azurewebsites.net')){$azureWebsitesHost=$true;$azureIndicators.Add("initial-hop redirect destination $azureRedirectHost")|Out-Null}}catch{}}
    foreach($azureDnsName in @($dns.CNames)+@($dns.ReverseDns)){if(Test-Suffix $azureDnsName @('azurewebsites.net')){$azureWebsitesHost=$true;$azureIndicators.Add("DNS/PTR $azureDnsName")|Out-Null}}
    if($Headers -is [Collections.IDictionary]){
        $setCookie=$null
        foreach($key in @($Headers.Keys)){
            $headerValue=[string]$Headers[$key]
            if([string]$key -ieq 'Set-Cookie'){$setCookie=$headerValue}
            if([string]$key -in @('X-ARR-Log-Id','X-Site-Deployment-Id','X-Ms-Routing-Name')){$azureStrongHeader=$true;$azureIndicators.Add("header $key")|Out-Null}
            elseif([string]$key -in @('X-Azure-Ref','X-Ms-Request-Id','X-Msedge-Ref')){$azureSupportingIndicators.Add("header $key")|Out-Null}
        }
        $azureArrAffinity=[bool]($setCookie -match '(?i)(?:^|[,;\s])ARRAffinity=')
        $azureArrAffinitySameSite=[bool]($setCookie -match '(?i)(?:^|[,;\s])ARRAffinitySameSite=')
        if($azureArrAffinity){$azureIndicators.Add('ARRAffinity cookie')|Out-Null}
        if($azureArrAffinitySameSite){$azureIndicators.Add('ARRAffinitySameSite cookie')|Out-Null}
    }
    $azureManagedPlatformLikely=($azureArrAffinity -or $azureArrAffinitySameSite -or $azureWebsitesHost -or $azureStrongHeader)
    $provider=$null;$serviceType=$null;$responsibility=$null;$hostingConfidence='Low';$signals=New-Object 'System.Collections.Generic.List[string]'
    $dnsProvider='Unknown';$dnsProviderEvidence='No known DNS-provider signature matched.'
    $nsText=(@($dns.NameServers)-join' ').ToLowerInvariant()
    foreach($rule in @(
        @{Pattern='domaincontrol\.com';Name='GoDaddy DNS'},@{Pattern='cloudflare\.com';Name='Cloudflare DNS'},@{Pattern='awsdns-';Name='Amazon Route 53'},
        @{Pattern='azure-dns\.';Name='Microsoft Azure DNS'},@{Pattern='googledomains\.com|google\.com';Name='Google Cloud DNS'},
        @{Pattern='wordpress\.com';Name='WordPress.com DNS'},@{Pattern='combell\.net';Name='Combell DNS'},@{Pattern='netfirms\.com';Name='Netfirms DNS'}
    )){if($nsText -match $rule.Pattern){$dnsProvider=$rule.Name;$dnsProviderEvidence="Nameserver signal matched $($rule.Pattern): $(@($dns.NameServers)-join', ')";break}}
    if($azureManagedPlatformLikely){
        $provider='Microsoft Azure managed platform';$serviceType='Managed-Likely Azure platform/front end';$responsibility='ManagedLikely';$hostingConfidence=if($azureArrAffinity -or $azureArrAffinitySameSite -or $azureWebsitesHost){'High'}else{'Medium'}
        foreach($item in @($azureIndicators)){$signals.Add($item)|Out-Null}
        foreach($item in @($azureSupportingIndicators)){$signals.Add("supporting $item")|Out-Null}
    }
    foreach ($profile in $script:ManagedProfiles) {
        if($provider){break}
        $score=0;$local=New-Object 'System.Collections.Generic.List[string]'
        foreach ($name in @($dns.CNames)+@($dns.ReverseDns)) {if(Test-Suffix $name $profile.CNameSuffixes){$score+=70;$local.Add("DNS/PTR $name")|Out-Null}}
        foreach ($name in @($dns.NameServers)) {if(Test-Suffix $name $profile.NsSuffixes){$score+=35;$local.Add("NS $name")|Out-Null}}
        if(Test-Suffix $effectiveHost $profile.HostSuffixes){$score+=60;$local.Add("effective host $effectiveHost")|Out-Null}
        if(-not [string]::IsNullOrWhiteSpace($RedirectDestination)){
            try{$redirectHost=([uri]$RedirectDestination).Host.ToLowerInvariant();if(Test-Suffix $redirectHost ($profile.CNameSuffixes+$profile.HostSuffixes)){$score+=70;$local.Add("initial-hop redirect destination $redirectHost")|Out-Null}}catch{}
        }
        if($Headers -is [Collections.IDictionary]){
            foreach($headerName in $profile.HeaderNames){foreach($key in @($Headers.Keys)){if([string]$key -ieq $headerName){$score+=45;$local.Add("header $key")|Out-Null}}}
            $serverValue=$null;foreach($key in @($Headers.Keys)){if([string]$key -ieq 'Server'){$serverValue=[string]$Headers[$key];break}}
            foreach($pattern in @(Get-SafeProperty $profile 'ServerPatterns')){if(-not [string]::IsNullOrWhiteSpace([string]$pattern) -and -not [string]::IsNullOrWhiteSpace($serverValue) -and $serverValue -match $pattern){$score+=80;$local.Add("Server header $serverValue matched $pattern")|Out-Null}}
        }
        if($score -ge 60){$provider=$profile.Name;$serviceType=$profile.ServiceType;$responsibility='Provider';$hostingConfidence=if($score -ge 90){'High'}else{'Medium'};foreach($item in $local){$signals.Add($item)|Out-Null};break}
    }
    if (-not $provider -and -not [string]::IsNullOrWhiteSpace($Content)) {
        if ($Content -match '(?is)Web Server.?s Default Page.*generated by\s*<a[^>]+plesk\.com|Log in to Plesk to create websites|Plesk.*hosting automation software') {
            $provider='Plesk-hosted environment';$serviceType='Hosting control-panel environment';$responsibility='Provider';$hostingConfidence='Medium'
            $signals.Add('Plesk default hosting page observed in HTTP response body')|Out-Null
        }
    }
    $matches=New-Object 'System.Collections.Generic.List[object]'
    foreach($address in @($dns.Addresses)){foreach($range in @($script:Catalog.Ranges)){if(Test-IpInCidr $address $range.Cidr){$matches.Add([pscustomobject]@{Address=$address;Provider=$range.Provider;ServiceType=$range.ServiceType;Responsibility=$range.Responsibility;Cidr=$range.Cidr;Source=$range.Source})|Out-Null}}}
    if(-not$provider){$preferred=@($matches|Where-Object{$_.Provider -ne 'Cloudflare'}|Select-Object -First 1);if($preferred.Count -gt 0){$m=$preferred[0];$provider=$m.Provider;$serviceType=$m.ServiceType;$responsibility=$m.Responsibility;$hostingConfidence='Medium';$signals.Add("$($m.Address) matched $($m.Cidr) from $($m.Source)")|Out-Null}}
    if($explicit.Found){$status=$explicit.Status;$patch=$explicit.PatchResponsibility;$confidence=$explicit.Confidence;$basis='Explicit input metadata';$evidence=$explicit.Evidence}
    elseif($responsibility -eq 'Provider'){$status='Assumed Provider Managed';$patch='No';$confidence=$hostingConfidence;$basis='Managed-platform attribution';$evidence=(@($signals)-join'; ');if($provider -eq 'Plesk-hosted environment'){$evidence += '. Plesk proves a hosting control-panel environment, not contractual patch ownership; confirm the hosting operator before closing remediation.'}}
    elseif($responsibility -eq 'ManagedLikely'){$status='Managed-Likely Azure Platform';$patch='Unknown - platform/front-end signal; custom container or backend ownership not established';$confidence=$hostingConfidence;$basis='Strong Azure managed-platform response evidence';$evidence=((@($signals)-join'; ')+'. Excluded from direct internal NGINX patch queue pending confirmation of built-in platform versus custom container/backend.')}
    elseif($responsibility -eq 'Customer'){$status='Assumed Organization/Customer Managed';$patch='Likely Yes';$confidence=$hostingConfidence;$basis='Generic cloud/IaaS attribution';$evidence=((@($signals)-join'; ')+'. Generic cloud infrastructure normally leaves guest software and workload patching with the customer; responsibility remains an operational assumption pending ownership confirmation.')}
    else{$status='Unknown';$patch='Unknown';$confidence='Low';$basis='No decisive provider or organization-controlled network evidence';$evidence='No recognized explicit value or decisive dynamic provider signal was established. DNS-provider identity alone is not hosting or patch-responsibility evidence.'}
    $risk=if($status -eq 'Managed-Likely Azure Platform'){'MANAGED-LIKELY - Verify Azure service model; exclude from direct patch queue'}elseif(($patch -eq 'Yes' -or $patch -eq 'Likely Yes') -and (-not$CloudflareDetected)){'HIGH ATTENTION - Customer-managed and Cloudflare not confirmed'}elseif($status -eq 'Unknown' -and (-not$CloudflareDetected)){'REVIEW - Management unknown and Cloudflare not confirmed'}else{'Standard review'}
    return [pscustomobject][ordered]@{
        Target=$Target;CanonicalHost=$effectiveHost;ManagementStatus=$status;OrganizationPatchResponsibility=$patch;ManagementConfidence=$confidence;ManagementBasis=$basis;ManagementEvidence=$evidence
        HostingProvider=if($provider){$provider}else{'Unknown'};HostingServiceType=if($serviceType){$serviceType}else{'Unknown'};HostingConfidence=if($provider){$hostingConfidence}else{'Low'};HostingEvidence=(@($signals)-join'; ')
        DnsProvider=$dnsProvider;DnsProviderEvidence=$dnsProviderEvidence;ResolvedAddresses=(@($dns.Addresses)-join';');CNameChain=(@($dns.CNames)-join';');NameServers=(@($dns.NameServers)-join';');ReverseDns=(@($dns.ReverseDns)-join';')
        MatchedProviderRanges=(@($matches|ForEach-Object{"$($_.Address)=$($_.Provider):$($_.Cidr)"})-join';');AzureManagedPlatformLikely=$azureManagedPlatformLikely;AzurePlatformConfidence=if($azureManagedPlatformLikely){$hostingConfidence}else{'Low'};AzurePlatformIndicators=(@($azureIndicators+$azureSupportingIndicators)-join';');AzureArrAffinityObserved=$azureArrAffinity;AzureArrAffinitySameSiteObserved=$azureArrAffinitySameSite;AzureWebsitesHostnameObserved=$azureWebsitesHost;AzureStrongHeaderObserved=$azureStrongHeader;CloudflareDetected=$CloudflareDetected;CloudflareIndicators=$CloudflareIndicators
        ExternalRiskPriority=$risk;AttributionEngineVersion=$script:EngineVersion;AttributionEvaluatedUtc=[datetime]::UtcNow.ToString('o')
    }
}

Export-ModuleMember -Function Initialize-AssetAttributionEngine,Get-AssetProviderAttribution,Get-ExplicitAssetManagement,Write-AttributionStatus
