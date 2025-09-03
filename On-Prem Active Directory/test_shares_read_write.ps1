<#
.SYNOPSIS
  Test read/write access and enumerate ACLs for shares listed in a CSV, with human-readable share types.

.DESCRIPTION
  - Imports shares from shared_folders.csv (exported via Invoke-ShareFinder | Export-Csv).
  - Converts the string “Type” field into a uint32 code.
  - Translates that code into Disk/PrintQueue/IPC (+ Administrative) via Get-ShareTypeName.
  - Tests each UNC path for read and write permissions.
  - Queries SMB share ACL entries via Get-SmbShareAccess.
  - Outputs results to console and writes ShareSecurityReport.csv.
#>

#---------------------------------------------------------------------------------------------------
function Get-ShareTypeName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint32]$TypeCode
    )

    # Check if the “special” (administrative) bit is set
    $isAdmin  = ($TypeCode -band 0x80000000) -ne 0

    # Mask off that bit to get the base type
    $baseType = $TypeCode -band 0x7FFFFFFF

    # Map base type to a friendly name
    $baseName = switch ($baseType) {
        0 { 'Disk' }
        1 { 'PrintQueue' }
        2 { 'Device' }
        3 { 'IPC' }
        default { "Unknown(0x{0:X})" -f $baseType }
    }

    if ($isAdmin) { "$baseName (Administrative)" } else { $baseName }
}
#---------------------------------------------------------------------------------------------------

# 1. File paths (ensure this script and the CSV live in the same folder)
$shareFile    = Join-Path $PSScriptRoot 'shared_folders.csv'
$outputReport = Join-Path $PSScriptRoot 'ShareSecurityReport.csv'

# 2. Validate input
if (-not (Test-Path $shareFile)) {
    Write-Error "Could not find input file: $shareFile"
    exit 1
}

# 3. Load shares
$shares = Import-Csv -Path $shareFile

# 4. Iterate and test
$results = foreach ($s in $shares) {
    # Build UNC path
    $uncPath = "\\$($s.ComputerName)\$($s.Name)"

    # Initialize flags
    $canRead  = $false
    $canWrite = $false

    # 4a. Read test
    if (Test-Path $uncPath) {
        $canRead = $true

        # 4b. Write test
        $tempFile = Join-Path $uncPath "perm_test_$([guid]::NewGuid()).txt"
        try {
            Set-Content -Path $tempFile -Value 'permission test' -ErrorAction Stop
            Remove-Item  -Path $tempFile -Force -ErrorAction SilentlyContinue
            $canWrite = $true
        } catch {
            $canWrite = $false
        }
    }

    # 4c. ACL query
    try {
        $entries = Get-SmbShareAccess `
            -ComputerName $s.ComputerName `
            -Name         $s.Name         `
            -ErrorAction  Stop |
          Select-Object AccountName,AccessControlType,AccessRight

        # Join ACL entries into a single string
        $shareAcl = (
            $entries |
            ForEach-Object { "$($_.AccountName):$($_.AccessControlType)/$($_.AccessRight)" } |
            Sort-Object -Unique
        ) -join '; '
    }
    catch {
        $shareAcl = 'ACL query failed'
    }

    # 4d. Decode share type
    $typeCode      = [uint32]$s.Type
    $shareTypeName = Get-ShareTypeName -TypeCode $typeCode

    # 4e. Build result object
    [PSCustomObject]@{
        Host       = $s.ComputerName
        Share      = $s.Name
        TypeCode   = $typeCode
        ShareType  = $shareTypeName
        Readable   = $canRead
        Writable   = $canWrite
        Share_ACL  = $shareAcl
    }
}

# 5. Display & Export
$results | Format-Table -AutoSize
$results | Export-Csv -Path $outputReport -NoTypeInformation

Write-Host "`nReport written to: $outputReport" -ForegroundColor Green