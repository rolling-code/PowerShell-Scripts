<#
.SYNOPSIS
    Finds enabled Active Directory users inactive for a specified number of days (default: 180),
    excluding the built-in Administrator account.

.DESCRIPTION
    Queries AD for users where all of the following are older than the inactivity threshold:
      - LastLogonTimestamp (replicated)
      - LastLogonDate      (non-replicated)
      - WhenCreated        (account creation date)
    Excludes the built-in Administrator by distinguished name.

.PARAMETER InactiveDays
    Number of days of inactivity to use as a cutoff. Defaults to 180.

.EXAMPLE
    .\Find-InactiveADUsers.ps1
    .\Find-InactiveADUsers.ps1 -InactiveDays 90

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]
    $InactiveDays = 180
)

# Ensure the ActiveDirectory module is available
Import-Module ActiveDirectory -ErrorAction Stop

# Compute the cutoff DateTime
$DateThreshold = (Get-Date).AddDays(-$InactiveDays)

# Fetch and filter users
$inactiveUsers = Get-ADUser `
    -Filter 'Enabled -eq $true' `
    -Properties LastLogonTimestamp, LastLogonDate, WhenCreated, DistinguishedName |
  Where-Object {
    # Convert the replicated LastLogonTimestamp (FileTime) to DateTime
    $llt = if ($_.LastLogonTimestamp) {
        [DateTime]::FromFileTime($_.LastLogonTimestamp)
    } else {
        [DateTime]::MinValue
    }

    # All three checks must be below the threshold
    ($llt           -lt $DateThreshold) -and
    ($_.LastLogonDate -lt $DateThreshold) -and
    ($_.WhenCreated   -lt $DateThreshold) -and
    # Exclude built-in Administrator (RID 500)
    (-not ($_.DistinguishedName -match ',CN=Administrator,'))
  }

# Output the results
$inactiveUsers |
  Select-Object `
    Name,
    SamAccountName,
    @{Name='LastLogonTimestamp';Expression={ if ($_.LastLogonTimestamp) { [DateTime]::FromFileTime($_.LastLogonTimestamp) } else { $null } }},
    LastLogonDate,
    WhenCreated |
  Format-Table -AutoSize