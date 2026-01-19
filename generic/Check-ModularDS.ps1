
<#
.SYNOPSIS
  Checks if a website is running the "Modular DS" WordPress plugin (slug: modular-connector)
  and determines whether the detected version is 2.5.1 or earlier.

.DESCRIPTION
  Safe, read-only heuristics:
    1) Tries to fetch /wp-content/plugins/modular-connector/readme.txt (and related files)
       and parse "Stable tag:" / "Version:" / changelog headings.
    2) (Optional) Heuristic: scans homepage HTML for references to
       /wp-content/plugins/modular-connector/ or /api/modular-connector/ (version may remain unknown).

  No requests are made to sensitive /api/modular-connector/* routes.

.PARAMETER Url
  Single site (domain or full URL), e.g. "https://example.com" or "example.com".

.PARAMETER InputFile
  Path to a file containing one target per line.

.PARAMETER TimeoutSec
  HTTP timeout per request (default 10).

.PARAMETER GuessFromHtml
  If set, also heuristically inspects homepage HTML for plugin traces (non-invasive).

.PARAMETER Parallel
  If set, processes list targets in parallel (PowerShell 7+).

.PARAMETER ThrottleLimit
  Degree of parallelism when -Parallel is used (default 16).

.PARAMETER SkipCertificateCheck
  Ignore TLS certificate errors (useful for lab/dev; requires PowerShell 7+).

.PARAMETER OutputPath
  Where to write JSON results. Defaults to ./modulards-scan-results.json

.EXAMPLE
  .\Check-ModularDS.ps1 -Url https://example.com

.EXAMPLE
  .\Check-ModularDS.ps1 -InputFile .\targets.txt -Parallel -ThrottleLimit 24 -GuessFromHtml

.NOTES
  PowerShell: 7+
#>

[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'Single', Position = 0)]
  [string]$Url,

  [Parameter(Mandatory = $true, ParameterSetName = 'List', Position = 0)]
  [string]$InputFile,

  [int]$TimeoutSec = 10,

  [switch]$GuessFromHtml,

  [switch]$Parallel,
  [int]$ThrottleLimit = 16,

  [switch]$SkipCertificateCheck,

  [string]$OutputPath = "$(Join-Path (Get-Location) 'modulards-scan-results.json')"
)

begin {
  $ErrorActionPreference = 'Stop'

  # Constants
  $PluginSlug = 'modular-connector'
  $VulnerableMax = [version]'2.5.1'

  # Candidate files to read version info from (ordered)
  $PathCandidates = @(
    "wp-content/plugins/$PluginSlug/readme.txt",
    "wp-content/plugins/$PluginSlug/README.txt",
    "wp-content/plugins/$PluginSlug/README.md",
    "wp-content/plugins/$PluginSlug/readme.md",
    "wp-content/plugins/$PluginSlug/changelog.txt",
    "wp-content/plugins/$PluginSlug/CHANGELOG.txt",
    "wp-content/plugins/$PluginSlug/CHANGELOG.md",
    "wp-content/plugins/$PluginSlug/changelog.md"
  )

  $Headers = @{
    'User-Agent' = 'Mozilla/5.0 (compatible; ModularDS-Checker/1.0; +https://localhost)'
    'Accept'      = 'text/plain, text/markdown, text/*;q=0.9, */*;q=0.8'
  }

  function Normalize-BaseUrl {
    param([string]$t)
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }
    $s = $t.Trim()
    if (-not ($s -match '^https?://')) { $s = "https://$s" }
    # strip trailing slash
    return $s.TrimEnd('/')
  }

  function Combine-Url {
    param([string]$base, [string]$path)
    return "$base/$path"
  }

  function Invoke-SafeRequest {
    param(
      [string]$Uri
    )
    try {
      $common = @{
        Uri                  = $Uri
        Headers              = $Headers
        Method               = 'GET'
        TimeoutSec           = $TimeoutSec
        MaximumRedirection   = 5
        ErrorAction          = 'Stop'
      }
      if ($PSBoundParameters.ContainsKey('SkipCertificateCheck') -and $SkipCertificateCheck) {
        $common['SkipCertificateCheck'] = $true  # PS 7+
      }
      return Invoke-WebRequest @common
    } catch {
      return $null
    }
  }

  function Parse-VersionFromText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    # Look for "Stable tag:" or "Version:" first
    $patterns = @(
      'Stable\s+tag:\s*([0-9]+(?:\.[0-9]+)*)',
      'Version:\s*([0-9]+(?:\.[0-9]+)*)'
    )

    foreach ($pat in $patterns) {
      $m = [regex]::Matches($Text, $pat, 'IgnoreCase')
      if ($m.Count -gt 0) {
        # Choose the highest parseable among matches (defensive)
        $candidates = $m | ForEach-Object { $_.Groups[1].Value }
        $best = $null
        foreach ($vstr in $candidates) {
          $ver = $null
          if ([version]::TryParse($vstr, [ref]$ver)) {
            if (-not $best -or $ver -gt $best) { $best = $ver }
          }
        }
        if ($best) { return $best.ToString() }
        return $candidates[0]
      }
    }

    # Fallback: scan changelog headings (e.g., "### 2.5.1", "= 2.5.1 =")
    $changelogPat = '^\s*(?:=+|#+)\s*v?([0-9]+(?:\.[0-9]+)+)\s*(?:=+)?\s*$'
    $matches = [regex]::Matches($Text, $changelogPat, 'IgnoreCase, Multiline')
    if ($matches.Count -gt 0) {
      $best = $null
      foreach ($m in $matches) {
        $ver = $null
        if ([version]::TryParse($m.Groups[1].Value, [ref]$ver)) {
          if (-not $best -or $ver -gt $best) { $best = $ver }
        }
      }
      if ($best) { return $best.ToString() }
    }

    return $null
  }

  function Is-Vulnerable {
    param([string]$VersionString)

    if ([string]::IsNullOrWhiteSpace($VersionString)) { return $null }

    $v = $null
    if ([version]::TryParse($VersionString, [ref]$v)) {
      return ($v -le $VulnerableMax)
    }

    # Fallback: coerce dotted numeric segments
    try {
      $parts = ($VersionString -split '[^\d]+') | Where-Object { $_ -ne '' } | Select-Object -First 4
      while ($parts.Count -lt 4) { $parts += '0' }
      $ver = [version]::new([int]$parts[0],[int]$parts[1],[int]$parts[2],[int]$parts[3])
      return ($ver -le $VulnerableMax)
    } catch {
      return $null
    }
  }

  function Heuristic-HomeHtml-HasModularDS {
    param([string]$BaseUrl)

    $resp = Invoke-SafeRequest -Uri $BaseUrl
    if (-not $resp -or [string]::IsNullOrWhiteSpace($resp.Content)) { return $false }

    # Non-invasive search for plugin traces
    if ($resp.Content -match '\/wp-content\/plugins\/modular-connector\/' -or
        $resp.Content -match '\/api\/modular-connector\/') {
      return $true
    }
    return $false
  }

  function Scan-Target {
    param([string]$Target)

    $base = Normalize-BaseUrl $Target
    if (-not $base) {
      return [pscustomobject]@{
        Target           = $Target
        PluginSlug       = $PluginSlug
        Detected         = $false
        Version          = $null
        IsVulnerable     = $null
        DetectionMethod  = 'invalid-url'
        Evidence         = $null
      }
    }

    $found   = $false
    $version = $null
    $method  = $null
    $evidence= $null

    foreach ($rel in $PathCandidates) {
      $u = Combine-Url $base $rel
      $r = Invoke-SafeRequest -Uri $u
      if ($r -and $r.StatusCode -ge 200 -and $r.StatusCode -lt 300 -and $r.Content) {
        $ver = Parse-VersionFromText -Text $r.Content
        if ($ver) {
          $found   = $true
          $version = $ver
          $method  = 'readme/changelog'
          $evidence= $u
          break
        } elseif ($r.Content -match '(?i)Modular\s*DS') {
          $found   = $true
          $method  = 'readme-present-no-version'
          $evidence= $u
          # keep looking for a better source that includes a version
        }
      } elseif ($r -and $r.StatusCode -eq 403) {
        # Access denied; continue with other heuristics.
        continue
      }
    }

    if (-not $found -and $GuessFromHtml) {
      if (Heuristic-HomeHtml-HasModularDS -BaseUrl "$base/") {
        $found   = $true
        $method  = 'home-html-heuristic'
        $evidence= "$base/"
      }
    }

    [pscustomobject]@{
      Target           = $Target
      PluginSlug       = $PluginSlug
      Detected         = $found
      Version          = $version
      IsVulnerable     = if ($version) { Is-Vulnerable -VersionString $version } else { $null }
      DetectionMethod  = $method
      Evidence         = $evidence
    }
  }
}

process {
  $targets =
    if ($PSCmdlet.ParameterSetName -eq 'List') {
      Get-Content -LiteralPath $InputFile | Where-Object { $_ -and $_.Trim() -ne '' }
    } else {
      @($Url)
    }

  if ($Parallel -and $targets.Count -gt 1) {
    $results = $targets | ForEach-Object -Parallel {
      # bring in needed vars
      $using:PSBoundParameters | Out-Null  # keep analyzer quiet
      # Recreate helper functions inside the parallel runspace
      $PluginSlug        = $using:PluginSlug
      $PathCandidates    = $using:PathCandidates
      $TimeoutSec        = $using:TimeoutSec
      $Headers           = $using:Headers
      $VulnerableMax     = $using:VulnerableMax
      $GuessFromHtml     = $using:GuessFromHtml
      $SkipCertificateCheck = $using:SkipCertificateCheck

      function Normalize-BaseUrl { param([string]$t)
        if ([string]::IsNullOrWhiteSpace($t)) { return $null }
        $s = $t.Trim(); if (-not ($s -match '^https?://')) { $s = "https://$s" }
        return $s.TrimEnd('/')
      }
      function Combine-Url { param([string]$base,[string]$path) "$base/$path" }
      function Invoke-SafeRequest { param([string]$Uri)
        try {
          $common = @{
            Uri                = $Uri
            Headers            = $Headers
            Method             = 'GET'
            TimeoutSec         = $TimeoutSec
            MaximumRedirection = 5
            ErrorAction        = 'Stop'
          }
          if ($SkipCertificateCheck) { $common['SkipCertificateCheck'] = $true }
          Invoke-WebRequest @common
        } catch { $null }
      }
      function Parse-VersionFromText { param([string]$Text)
        if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
        $patterns = @('Stable\s+tag:\s*([0-9]+(?:\.[0-9]+)*)','Version:\s*([0-9]+(?:\.[0-9]+)*)')
        foreach ($pat in $patterns) {
          $m = [regex]::Matches($Text, $pat, 'IgnoreCase')
          if ($m.Count -gt 0) {
            $candidates = $m | ForEach-Object { $_.Groups[1].Value }
            $best = $null
            foreach ($vstr in $candidates) { $ver = $null; if ([version]::TryParse($vstr, [ref]$ver)) { if (-not $best -or $ver -gt $best) { $best = $ver } } }
            if ($best) { return $best.ToString() }; return $candidates[0]
          }
        }
        $matches = [regex]::Matches($Text, '^\s*(?:=+|#+)\s*v?([0-9]+(?:\.[0-9]+)+)\s*(?:=+)?\s*$', 'IgnoreCase, Multiline')
        if ($matches.Count -gt 0) {
          $best = $null
          foreach ($m in $matches) { $ver = $null; if ([version]::TryParse($m.Groups[1].Value, [ref]$ver)) { if (-not $best -or $ver -gt $best) { $best = $ver } } }
          if ($best) { return $best.ToString() }
        }
        $null
      }
      function Is-Vulnerable { param([string]$VersionString)
        if ([string]::IsNullOrWhiteSpace($VersionString)) { return $null }
        $v = $null
        if ([version]::TryParse($VersionString, [ref]$v)) { return ($v -le $VulnerableMax) }
        try {
          $parts = ($VersionString -split '[^\d]+') | Where-Object { $_ -ne '' } | Select-Object -First 4
          while ($parts.Count -lt 4) { $parts += '0' }
          $ver = [version]::new([int]$parts[0],[int]$parts[1],[int]$parts[2],[int]$parts[3])
          return ($ver -le $VulnerableMax)
        } catch { $null }
      }
      function Heuristic-HomeHtml-HasModularDS { param([string]$BaseUrl)
        $resp = Invoke-SafeRequest -Uri $BaseUrl
        if (-not $resp -or [string]::IsNullOrWhiteSpace($resp.Content)) { return $false }
        if ($resp.Content -match '\/wp-content\/plugins\/modular-connector\/' -or
            $resp.Content -match '\/api\/modular-connector\/') { return $true }
        $false
      }
      function Scan-Target { param([string]$Target)
        $base = Normalize-BaseUrl $Target
        if (-not $base) {
          return [pscustomobject]@{ Target=$Target; PluginSlug=$PluginSlug; Detected=$false; Version=$null; IsVulnerable=$null; DetectionMethod='invalid-url'; Evidence=$null }
        }
        $found=$false; $version=$null; $method=$null; $evidence=$null
        foreach ($rel in $PathCandidates) {
          $u = Combine-Url $base $rel
          $r = Invoke-SafeRequest -Uri $u
          if ($r -and $r.StatusCode -ge 200 -and $r.StatusCode -lt 300 -and $r.Content) {
            $ver = Parse-VersionFromText -Text $r.Content
            if ($ver) { $found=$true; $version=$ver; $method='readme/changelog'; $evidence=$u; break }
            elseif ($r.Content -match '(?i)Modular\s*DS') { $found=$true; $method='readme-present-no-version'; $evidence=$u }
          } elseif ($r -and $r.StatusCode -eq 403) {
            continue
          }
        }
        if (-not $found -and $GuessFromHtml) {
          if (Heuristic-HomeHtml-HasModularDS -BaseUrl "$base/") { $found=$true; $method='home-html-heuristic'; $evidence="$base/" }
        }
        [pscustomobject]@{
          Target          = $Target
          PluginSlug      = $PluginSlug
          Detected        = $found
          Version         = $version
          IsVulnerable    = if ($version) { Is-Vulnerable -VersionString $version } else { $null }
          DetectionMethod = $method
          Evidence        = $evidence
        }
      }

      Scan-Target -Target $_
    } -ThrottleLimit $ThrottleLimit
  } else {
    $results = foreach ($t in $targets) { Scan-Target -Target $t }
  }

  # Display & persist
  $results | Sort-Object Target | Format-Table -AutoSize
  $results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding utf8
  Write-Host "`nSaved JSON results to: $OutputPath"
}
