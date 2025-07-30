Import-Module GroupPolicy

# Define which permissions you care about
$targetPerms = 'GpoRead','GpoEdit','GpoAll'

Get-GPO -All | ForEach-Object {
    $gpo = $_

    # Fetch all ACL entries on this GPO, then filter by our target permissions
    Get-GPPermissions -Guid $gpo.Id -All |
      Where-Object { $targetPerms -contains $_.Permission } |
      Select-Object `
        @{Name='GPO';        Expression={$gpo.DisplayName}},
        @{Name='Trustee';    Expression={$_.Trustee}},
        @{Name='Permission'; Expression={$_.Permission}}
} |
# Optional: format as a tidy table
Format-List GPO, Trustee, Permission