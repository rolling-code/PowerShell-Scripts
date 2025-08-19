# Ensure the ActiveDirectory module is available
Import-Module ActiveDirectory

# 1. Grab all users with Enabled status and creation date
$allUsers = Get-ADUser -Filter * `
    -Properties Enabled, WhenCreated, LastLogonDate

# 2. Build the report
$report = foreach ($user in $allUsers) {
	
	# 1. Grab the raw DistinguishedName
	$userDnRaw = $user.DistinguishedName
	
	# 2. Double any apostrophes for the AD filter
	$userDnEscaped = $userDnRaw -replace "'", "''"

    # Normalize user info
    #$userDn        = $user.DistinguishedName
    $userName      = $user.SamAccountName
    $displayName   = $user.Name
    $userEnabled   = if ($user.Enabled) { 'Active' } else { 'Disabled' }
    #$createdOn     = $user.WhenCreated.ToString('yyyy-MM-dd')
	$createdOn = if ($user.WhenCreated) {
					$user.WhenCreated.ToString('yyyy-MM-dd')
				} else {
					'<n/a>'
				}



	# 3. Use the escaped DN in a single-quoted filter string
	$computers = Get-ADComputer -Filter "ManagedBy -eq '$userDnEscaped'" ` -Properties Enabled, LastLogonDate

    if ($computers) {
        # One row per computer
        foreach ($comp in $computers) {
            [PSCustomObject]@{
                UserName         = $userName
                DisplayName      = $displayName
                UserStatus       = $userEnabled
                UserCreated      = $createdOn
                ComputerName     = $comp.Name
                ComputerStatus   = if ($comp.Enabled) { 'Active' } else { 'Disabled' }
            }
        }
    }
    else {
        # User with no assigned computers
        [PSCustomObject]@{
            UserName         = $userName
            DisplayName      = $displayName
            UserStatus       = $userEnabled
            UserCreated      = $createdOn
            ComputerName     = '<none>'
            ComputerStatus   = '<n/a>'
        }
    }
}

# 4. Output to CSV (change path as needed)
$csvPath = ".\AD-UserComputer-Audit.csv"
$report | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "Report generated at $csvPath" -ForegroundColor Green