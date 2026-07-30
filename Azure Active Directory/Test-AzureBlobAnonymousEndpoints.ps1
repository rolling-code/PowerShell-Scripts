#requires -Version 7.0
<#
.SYNOPSIS
Performs unauthenticated HTTP validation of Azure Blob endpoints.

.DESCRIPTION
Reads a CSV containing StorageAccountName and ContainerName, then uses curl.exe
without Azure credentials, storage keys, cookies, or SAS tokens to test anonymous
container listing. If the optional ExactBlobName column contains a known blob path,
the script also requests only the first byte to validate anonymous exact-object read
access without downloading the full object.

.PARAMETER InputCsv
CSV containing StorageAccountName and ContainerName. Optional columns are
ContainerPublicAccess and ExactBlobName.

.PARAMETER OutputDirectory
Directory in which evidence files and the summary CSV are written.

.EXAMPLE
./Test-AzureBlobAnonymousEndpoints.ps1 -InputCsv ./StorageContainerPublicAccessDetails.csv

.EXAMPLE
./Test-AzureBlobAnonymousEndpoints.ps1 -InputCsv ./containers.csv -OutputDirectory ./http-evidence
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD 'AzureBlobAnonymousHttpEvidence')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    throw 'curl.exe was not found in PATH.'
}

New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null

$inputRows = @(Import-Csv -Path $InputCsv)
if ($inputRows.Count -eq 0) {
    throw 'The input CSV contains no rows.'
}

$requiredColumns = @('StorageAccountName', 'ContainerName')
$availableColumns = @($inputRows[0].PSObject.Properties.Name)
foreach ($column in $requiredColumns) {
    if ($column -notin $availableColumns) {
        throw "The input CSV must contain a '$column' column."
    }
}

$hasPublicAccessColumn = 'ContainerPublicAccess' -in $availableColumns
$hasExactBlobNameColumn = 'ExactBlobName' -in $availableColumns

$targets = @(
    $inputRows | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.StorageAccountName) -and
        -not [string]::IsNullOrWhiteSpace([string]$_.ContainerName) -and
        (-not $hasPublicAccessColumn -or [string]$_.ContainerPublicAccess -in @('Blob', 'Container'))
    }
)

if ($targets.Count -eq 0) {
    throw 'No valid container targets were found in the input CSV.'
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$results = [System.Collections.Generic.List[object]]::new()

function ConvertTo-UrlEncodedBlobPath {
    param([Parameter(Mandatory)][string]$BlobName)

    $segments = $BlobName -split '/'
    return (($segments | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/')
}

function Invoke-CurlEvidenceRequest {
    param(
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter(Mandatory)][string]$ContainerName,
        [Parameter(Mandatory)][ValidateSet('ContainerList', 'ExactBlobRead')][string]$CheckType,
        [Parameter(Mandatory)][string]$Uri
    )

    $safeAccount = $StorageAccountName -replace '[^a-zA-Z0-9.-]', '_'
    $safeContainer = $ContainerName -replace '[^a-zA-Z0-9.-]', '_'
    $safeType = $CheckType.ToLowerInvariant()
    $baseName = "$safeAccount--$safeContainer--$safeType"
    $headerFile = Join-Path $OutputDirectory "$baseName--headers.txt"
    $bodyFile = Join-Path $OutputDirectory "$baseName--body.bin"
    $errorFile = Join-Path $OutputDirectory "$baseName--curl-error.txt"

    $curlArguments = @(
        '--silent'
        '--show-error'
        '--connect-timeout', '10'
        '--max-time', '30'
        '--dump-header', $headerFile
        '--output', $bodyFile
        '--write-out', '%{http_code}'
        '-H', 'x-ms-version: 2023-11-03'
    )

    if ($CheckType -eq 'ExactBlobRead') {
        $curlArguments += @('-H', 'Range: bytes=0-0')
    }

    $curlArguments += $Uri

    Write-Host "[$CheckType] $Uri" -ForegroundColor Cyan
    $httpCode = & curl.exe @curlArguments 2> $errorFile
    $curlExitCode = $LASTEXITCODE
    $httpCode = ([string]$httpCode).Trim()
    if ([string]::IsNullOrWhiteSpace($httpCode)) {
        $httpCode = '000'
    }

    $interpretation = if ($curlExitCode -ne 0) {
        'CurlNetworkOrDnsFailure'
    }
    elseif ($CheckType -eq 'ContainerList' -and $httpCode -eq '200') {
        'AnonymousContainerEnumerationConfirmed'
    }
    elseif ($CheckType -eq 'ContainerList' -and $httpCode -in @('401', '403', '409')) {
        'AnonymousContainerEnumerationDenied'
    }
    elseif ($CheckType -eq 'ExactBlobRead' -and $httpCode -in @('200', '206')) {
        'AnonymousExactBlobReadConfirmed'
    }
    elseif ($CheckType -eq 'ExactBlobRead' -and $httpCode -in @('401', '403')) {
        'AnonymousExactBlobReadDenied'
    }
    elseif ($httpCode -eq '404') {
        'NotFound-Inconclusive'
    }
    else {
        'ReviewResponse'
    }

    $results.Add([pscustomobject]@{
        Timestamp          = (Get-Date).ToString('o')
        CheckType          = $CheckType
        StorageAccountName = $StorageAccountName
        ContainerName      = $ContainerName
        Uri                = $Uri
        CurlExitCode       = $curlExitCode
        HttpStatus         = $httpCode
        Interpretation     = $interpretation
        HeaderFile         = $headerFile
        BodyFile           = $bodyFile
        CurlErrorFile      = $errorFile
    })

    Write-Host "HTTP $httpCode | curl exit $curlExitCode | $interpretation"
}

foreach ($target in $targets) {
    $account = [string]$target.StorageAccountName
    $container = [string]$target.ContainerName
    $listUri = "https://${account}.blob.core.windows.net/${container}?restype=container&comp=list"

    Invoke-CurlEvidenceRequest `
        -StorageAccountName $account `
        -ContainerName $container `
        -CheckType ContainerList `
        -Uri $listUri

    if ($hasExactBlobNameColumn -and -not [string]::IsNullOrWhiteSpace([string]$target.ExactBlobName)) {
        $encodedBlobPath = ConvertTo-UrlEncodedBlobPath -BlobName ([string]$target.ExactBlobName)
        $blobUri = "https://${account}.blob.core.windows.net/${container}/${encodedBlobPath}"

        Invoke-CurlEvidenceRequest `
            -StorageAccountName $account `
            -ContainerName $container `
            -CheckType ExactBlobRead `
            -Uri $blobUri
    }
}

$summaryCsv = Join-Path $OutputDirectory "AnonymousBlobHttpValidation-$timestamp.csv"
$results |
    Sort-Object StorageAccountName, ContainerName, CheckType |
    Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding utf8

$enumerable = @($results | Where-Object Interpretation -eq 'AnonymousContainerEnumerationConfirmed')
$exactReads = @($results | Where-Object Interpretation -eq 'AnonymousExactBlobReadConfirmed')
$failures = @($results | Where-Object CurlExitCode -ne 0)

Write-Host ''
Write-Host '=== Anonymous Blob HTTP Validation ===' -ForegroundColor Cyan
Write-Host "Container targets tested       : $($targets.Count)"
Write-Host "Anonymous enumeration confirmed: $($enumerable.Count)" -ForegroundColor $(if ($enumerable.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "Anonymous exact reads confirmed: $($exactReads.Count)" -ForegroundColor $(if ($exactReads.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "Curl/network failures          : $($failures.Count)" -ForegroundColor Yellow
Write-Host "Summary report                 : $summaryCsv" -ForegroundColor Cyan
Write-Host "Evidence directory             : $OutputDirectory" -ForegroundColor Cyan
Write-Host 'Read-only validation complete. No Azure resources were modified.' -ForegroundColor Green
