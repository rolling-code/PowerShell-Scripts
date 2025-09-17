param(
    [Parameter(Position=0, Mandatory=$true)]
    [string]$UNCPath,

    [Parameter(Position=1, Mandatory=$true)]
    [string]$ReportPath
)

function Get-FileContentText {
    param([string]$FilePath)

    try {
        $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()

        switch ($ext) {
            ".docx" {
                $word = $null; $doc = $null
                try {
                    $word = New-Object -ComObject Word.Application
                    $word.Visible = $false
                    $doc = $word.Documents.Open($FilePath, $false, $true)
                    $text = $doc.Content.Text
                    return $text
                } finally {
                    if ($doc) { $doc.Close() }
                    if ($word) { $word.Quit() }
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc) | Out-Null
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
                }
            }

            ".doc" {
                # Handle old .doc too using Word COM
                $word = $null; $doc = $null
                try {
                    $word = New-Object -ComObject Word.Application
                    $word.Visible = $false
                    $doc = $word.Documents.Open($FilePath, $false, $true)
                    $text = $doc.Content.Text
                    return $text
                } finally {
                    if ($doc) { $doc.Close() }
                    if ($word) { $word.Quit() }
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc) | Out-Null
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
                }
            }

            ".xlsx" {
					# best-practice Excel open: explicit args, read-only, retries, and COM cleanup
					$excel = $null; $wb = $null
					try {
						$maxAttempts = 3
						$attempt = 0
						$success = $false

						# Create Excel COM object once
						$excel = New-Object -ComObject Excel.Application
						$excel.DisplayAlerts = $false
						$excel.AskToUpdateLinks = $false
						$excel.AlertBeforeOverwriting = $false

						while (-not $success -and $attempt -lt $maxAttempts) {
							$attempt++
							try {
								# Workbooks.Open parameters (positional):
								# FileName, UpdateLinks, ReadOnly, Format, Password, WriteResPassword, IgnoreReadOnlyRecommended, Origin, Delimiter, Editable, Notify, Converter, AddToMru, Local, CorruptLoad
								# Using UpdateLinks=0 (don't update external links), ReadOnly=$true
								$wb = $excel.Workbooks.Open($FilePath, 0, $true)
								$success = $true
							} catch {
								Start-Sleep -Milliseconds 500
								if ($attempt -ge $maxAttempts) { throw }
							}
						}

						# Proceed only if opened
						if ($success -and $wb -ne $null) {
							# read data efficiently (Value2) then close workbook
							$allText = New-Object System.Text.StringBuilder
							foreach ($sheet in $wb.Worksheets) {
								$used = $sheet.UsedRange
								if ($used -ne $null) {
									$vals = $used.Value2
									if ($vals -is [object[,]]) {
										for ($r = 1; $r -le $vals.GetLength(0); $r++) {
											for ($c = 1; $c -le $vals.GetLength(1); $c++) {
												if ($vals[$r,$c] -ne $null) { $allText.AppendLine($vals[$r,$c].ToString()) | Out-Null }
											}
										}
									} elseif ($vals -ne $null) {
										$allText.AppendLine($vals.ToString()) | Out-Null
									}
									[System.Runtime.Interopservices.Marshal]::ReleaseComObject($used) | Out-Null
								}
								[System.Runtime.Interopservices.Marshal]::ReleaseComObject($sheet) | Out-Null
							}
							$content = $allText.ToString()
						} else {
							$content = "[Error opening workbook]"
						}
					} finally {
						if ($wb) { $wb.Close($false) }
						if ($excel) { $excel.Quit() }
						if ($wb) { [System.Runtime.Interopservices.Marshal]::ReleaseComObject($wb) | Out-Null }
						if ($excel) { [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null }
						[GC]::Collect(); [GC]::WaitForPendingFinalizers()
					}
				}

            ".xls" {
                # Legacy Excel
                return Get-FileContentText -FilePath $FilePath.Replace('.xls','.xlsx')
            }

            ".pdf" {
                # Try to use pdftotext if available; fall back to an error message
                $pdftotextPath = "pdftotext" # assumes in PATH
                try {
                    $out = & $pdftotextPath -layout -q -- "$FilePath" - 2>$null
                    if ($LASTEXITCODE -ne 0 -or -not $out) {
                        return "[Error reading PDF or pdftotext not available]"
                    }
                    return $out
                } catch {
                    return "[Error reading PDF or pdftotext not available]"
                }
            }

            default {
                return Get-Content -Path $FilePath -Raw -ErrorAction Stop
            }
        }
    } catch {
        return "[Error reading file]"
    }
}

function Decode-Base64 {
    param([string]$Content)
    try {
        $bytes = [System.Convert]::FromBase64String($Content)
        $decoded = [System.Text.Encoding]::UTF8.GetString($bytes)
        return $decoded
    } catch {
        return $null
    }
}

function Search-SensitiveData {
    param([string]$Content)
    $findings = @()

    if (-not $Content) { return $findings }

    if ($Content -match 'AKIA[0-9A-Z]{16}') { $findings += "AWS Access Key" }
    if ($Content -match 'AIza[0-9A-Za-z\-_]{35}') { $findings += "Google API Key" }
    if ($Content -match 'ghp_[A-Za-z0-9]{36}') { $findings += "GitHub Token" }
    if ($Content -match 'do_[A-Za-z0-9]{64}') { $findings += "DigitalOcean Token" }
    if ($Content -match 'xox[baprs]-[A-Za-z0-9-]+') { $findings += "Slack Token" }
    if ($Content -match 'sk_live_[A-Za-z0-9]{24}') { $findings += "Stripe Secret Key" }
    if ($Content -match '"apiKey"\s*:\s*"[^"]+"') { $findings += "Firebase API Key" }

    if ($Content -match '-----BEGIN (RSA|PRIVATE) KEY-----') { $findings += "Private Key" }
    if ($Content -match '"password"\s*:\s*"[^"]+"') { $findings += "Cleartext Password" }
    if ($Content -match 'Server=.*;Database=.*;User Id=.*;Password=.*;') { $findings += "DB Connection String" }
    if ($Content -match 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+') { $findings += "JWT Token" }

    if ($Content -match '<Directory.*>') { $findings += "Apache Config" }
    if ($Content -match 'listen\s+80') { $findings += "Nginx Default Port" }
    if ($Content -match 'spring.datasource.url') { $findings += "Spring DB Config" }
    if ($Content -match 'ejb-jar') { $findings += "EJB Config" }
    if ($Content -match 'define\(\s*"DB_PASSWORD"') { $findings += "WordPress DB Password" }
    if ($Content -match 'DB_USER=.*DB_PASSWORD=.*') { $findings += ".env Credentials" }

    return $findings
}

function Get-SourceType {
    param([string]$FilePath)
    switch ([System.IO.Path]::GetExtension($FilePath).ToLower()) {
        ".docx" { return "Word" }
        ".doc"  { return "Word" }
        ".xlsx" { return "Excel" }
        ".xls"  { return "Excel" }
        ".pdf"  { return "PDF" }
        default { return "Text/Other" }
    }
}

$results = New-Object System.Collections.Generic.List[object]
$processed = 0
$errors = 0

Get-ChildItem -Path $UNCPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $filePath = $_.FullName
    $sourceType = Get-SourceType -FilePath $filePath

    # Progress output
    Write-Host ("Processing: {0}  [Type: {1}]" -f $filePath, $sourceType)

    try {
        $content = Get-FileContentText -FilePath $filePath
        $processed++

        $matches = Search-SensitiveData -Content $content
        foreach ($match in $matches) {
            $snippet = ($content -replace "`r`n|`n|`r", ' ') -replace '^\s+|\s+$',''
            if ($snippet.Length -gt 100) { $snippet = $snippet.Substring(0,100) + "..." }
            $results.Add([PSCustomObject]@{
                FilePath = $filePath
                Source = $sourceType
                Finding = $match
                Snippet = $snippet
            }) | Out-Null
        }

        # Base64 detection: require longer strings to reduce false positives
        $base64Pattern = '(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{40,}(?:={0,2})(?![A-Za-z0-9+/=])'
        $base64Matches = [regex]::Matches($content, $base64Pattern)
        foreach ($m in $base64Matches) {
            $decoded = Decode-Base64 -Content $m.Value
            if ($decoded) {
                $decodedFindings = Search-SensitiveData -Content $decoded
                foreach ($df in $decodedFindings) {
                    $snippet = ($decoded -replace "`r`n|`n|`r", ' ') -replace '^\s+|\s+$',''
                    if ($snippet.Length -gt 100) { $snippet = $snippet.Substring(0,100) + "..." }
                    $results.Add([PSCustomObject]@{
                        FilePath = $filePath
                        Source = $sourceType
                        Finding = "Decoded: $df"
                        Snippet = $snippet
                    }) | Out-Null
                }
            }
        }

    } catch {
        $errors++
        Write-Warning "Failed to process $filePath : $_"
    }
}

# Export results if any
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host "Audit complete. Report saved to $ReportPath"
} else {
    # Create an empty CSV with headers so downstream processes don't fail
    $empty = [PSCustomObject]@{ FilePath=''; Source=''; Finding=''; Snippet='' }
    $empty | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host "Audit complete. No findings. Created empty report at $ReportPath"
}

Write-Host "Files processed: $processed  Errors: $errors"