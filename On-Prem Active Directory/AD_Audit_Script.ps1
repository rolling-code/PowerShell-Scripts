
# Import PowerView
Import-Module .\PowerView.ps1

# Get current timestamp for the report
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = "AD_Audit_Report_$timestamp.txt"

# Function to write output to the report file
function Write-Report {
    param (
        [string]$content
    )
    Add-Content -Path $reportPath -Value $content
}

# Start the report
Write-Report "Active Directory Audit Report - $timestamp"
Write-Report "========================================="
Write-Report ""

# User & Account Auditing
Write-Report "User & Account Auditing"
Write-Report "-----------------------"

# Users with passwords that never expire
Write-Report "Users with Passwords that Never Expire:"
Get-DomainUser -Properties PasswordNeverExpires | Where-Object { $_.PasswordNeverExpires -eq $true } | Select-Object samaccountname,description | ForEach-Object { Write-Report $_.samaccountname + " - " + $_.description }
Write-Report ""

# Users who can delegate
Write-Report "Users Who Can Delegate:"
Get-DomainUser -TrustedToAuth | Select-Object samaccountname,description | ForEach-Object { Write-Report $_.samaccountname + " - " + $_.description }
Write-Report ""

# Users with "admin" or "password" in their description
Write-Report "Users with 'admin' or 'password' in their Description:"
Get-DomainUser | Where-Object { $_.description -match "admin|password" } | Select-Object samaccountname,description | ForEach-Object { Write-Report $_.samaccountname + " - " + $_.description }
Write-Report ""

# Group & Privilege Auditing
Write-Report "Group & Privilege Auditing"
Write-Report "--------------------------"

# List all domain groups
Write-Report "All Domain Groups:"
Get-DomainGroup | Select-Object name | ForEach-Object { Write-Report $_.name }
Write-Report ""

# Find members of Domain Admins
Write-Report "Members of Domain Admins:"
Get-DomainGroupMember -Identity "Domain Admins" | Select-Object samaccountname | ForEach-Object { Write-Report $_.samaccountname }
Write-Report ""

# Find nested group memberships
Write-Report "Nested Group Memberships of Administrators:"
Get-DomainGroupMember -Recurse -Identity "Administrators" | Select-Object samaccountname | ForEach-Object { Write-Report $_.samaccountname }
Write-Report ""

# Computer & Host Recon
Write-Report "Computer & Host Recon"
Write-Report "---------------------"

# All domain-joined computers
Write-Report "All Domain-Joined Computers:"
Get-DomainComputer | Select-Object name | ForEach-Object { Write-Report $_.name }
Write-Report ""

# Computers with unconstrained delegation
Write-Report "Computers with Unconstrained Delegation:"
Get-DomainComputer -Unconstrained | Select-Object name | ForEach-Object { Write-Report $_.name }
Write-Report ""

# Computers with sensitive service accounts
Write-Report "Computers with Sensitive Service Accounts:"
Get-DomainComputer -TrustedToAuth | Select-Object name | ForEach-Object { Write-Report $_.name }
Write-Report ""

# ACL & Object Permissions
Write-Report "ACL & Object Permissions"
Write-Report "------------------------"

# Find users/groups with rights over other users
Write-Report "Users/Groups with Rights Over Other Users:"
Find-InterestingDomainAcl | ForEach-Object { Write-Report $_ }
Write-Report ""

# Find objects with GenericAll or WriteDACL permissions
Write-Report "Objects with GenericAll or WriteDACL Permissions:"
Find-ObjectAbuse -ResolveGUIDs | ForEach-Object { Write-Report $_ }
Write-Report ""

# Trusts & Domain Structure
Write-Report "Trusts & Domain Structure"
Write-Report "-------------------------"

# Get domain trust relationships
Write-Report "Domain Trust Relationships:"
Get-DomainTrust | ForEach-Object { Write-Report $_ }
Write-Report ""

# Get domain policy info
Write-Report "Domain Policy Info:"
Get-DomainPolicy | ForEach-Object { Write-Report $_ }
Write-Report ""

# SPN & Kerberoasting
Write-Report "SPN & Kerberoasting"
Write-Report "-------------------"

# Find users with SPNs
Write-Report "Users with SPNs:"
Get-DomainUser -SPN * | Select-Object samaccountname,serviceprincipalname | ForEach-Object { Write-Report $_.samaccountname + " - " + $_.serviceprincipalname }
Write-Report ""

# Request TGS tickets for all SPNs and output in hashcat format
Write-Report "Kerberoasting Tickets (Hashcat Format):"
Get-DomainUser -SPN * | Get-DomainSPNTicket -OutputFormat Hashcat | ForEach-Object { Write-Report $_ }
Write-Report ""

Write-Report "Audit Complete"
