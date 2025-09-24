
PowerShell-Scripts

A collection of PowerShell scripts for various administrative tasks, including Azure Active Directory and On-Prem Active Directory management.

Folder Structure:

```
PowerShell-Scripts/
├── generic/
│   └── Base64Tool.ps1
│   └── Test-Feeds3.ps1
├── Azure Active Directory/
│   └── get_az_token.ps1
│   └── aadinternals_audit6.ps1 (Uses AADInternals)
│   └── get_policies.ps1
│   └── grant_consent_MSGraph.ps1
│   └── sendmail.py
│   └── domains2ipsipv4Only.ps1
│   └── enum_entra_admins.ps1 & find_disabled_ad_accounts.ps1
│   └── list_all_applications2.ps1 & BulkMultiPermExploitability2.ps1 & Profile-App.ps1 & Audit-AppDelegationRisks.ps1
├── On-Prem Active Directory/
│   └── ad_object_permissions3.ps1 (uses ActiveDirectory module (ADWS))
│   └── delegated_rights.ps1 (uses ActiveDirectory module (ADWS))
│   └── servers_get_smb.ps1 (uses ActiveDirectory module (ADWS))
│   └── gpo_delegation_check2.ps1 (imports modules: GroupPolicy)
│   └── whois_islocal_admin2.ps1
│   └── check_blank_password_users.ps1 (uses ActiveDirectory module (ADWS))
│   └── check_PSSession_blank_passwords2.ps1 (uses ActiveDirectory module (ADWS))
│   └── check_smb_settings_all_domain_joined_pc_using_ps_remoting.ps1 (uses ActiveDirectory module (ADWS))
│   └── check_smb_settings_all_domain_joined_pc_using_wmi_and_remote_registry.ps1 (uses ActiveDirectory module (ADWS) and WMI)
│   └── inactive_users.ps1 (uses ActiveDirectory module (ADWS))
│   └── is_ldap_signing_enabled.ps1 (relies on raw LDAP/ADSI)
│   └── replicate_permissions.ps1 (uses ActiveDirectory module (ADWS))
│   └── replicated_rights2.ps1 (uses ActiveDirectory module (ADWS))
│   └── setNoPreauth.ps1
│   └── AD_Audit_Script.ps1 (uses PowerSploit and ActiveDirectory module (ADWS))
│   └── GpoAclAudit.ps1 (uses PowerSploit)
│   └── GetUsersAndTheirManagedByMachines.ps1 (uses ActiveDirectory module (ADWS))
│   └── test_shares_read_write.ps1
│   └── analyze_gpo3.ps1 (imports modules: GroupPolicy)
│   └── lan_audit_full2.ps1
└── README.md
```

Usage:

1. Clone the repository:
   git clone https://github.com/rolling-code/PowerShell-Scripts.git

2. Navigate to the desired folder:
   cd "PowerShell-Scripts/Azure Active Directory"

3. Run the script using PowerShell:
   .\get_az_token.ps1

Notes:

- Scripts are organized by domain (e.g., Azure AD, On-Prem AD).
- Contributions and suggestions are welcome!

## ── 📂 Section: Azure Active Directory ──
---
### `get_az_token.ps1`

**What a Successful Token Response Implies**

If you get a token back:

The app **does not require MFA** (since ROPC cannot satisfy MFA).

The user is **allowed to authenticate with just username and password**.

The app is **not blocked by Conditional Access** or **federation restrictions**.
 

In other words, if anything other than 400 (Bad Request) is returned it may indicate a problem.

To make it easier to spot I made the output of a successful token obtainment in RED.

Under https://intune.microsoft.com/ under the User's Sign-in logs (the user you specifid in the script) you can see the errors when MFA is expected but not used:

**Sign-in error** code `50076` in Azure AD **indicates that MFA (Multi-Factor Authentication) is required**.

Notice the PowerShell user agent given we are using API calls from PS
![Notice the PowerShell user agent](Azure%20Active%20Directory/docs/image-20250514-202526.png)

Notice the MFA requirement error description, as expected.
![Notice the MFA requirement](Azure%20Active%20Directory/docs/image-20250514-202748.png)

---
### `aadinternals_audit6.ps1`

Uses AADinternals to run Eight security checks on the tenant.

1) Global Admins (≤ 5)
2) Conditional Access – MFA for All Users
3) Security Defaults Disabled
4) MFA Status
5) Access Package Catalogs Present
6) Service Principals Without Roles
7) Tenant Settings – DirSync & SSPR
8) Block Legacy Authentication

---
### `get_policies.ps1` (Must be granted access to MS Graph!)

Determines which Azure AD Conditional Access (CA) policies apply to a specific user, evaluating both direct user inclusion/exclusion and group or role–based assignments.

Use like so:
`.\get_policies.ps1 userPrincipalname@domain.net`

Microsoft Graph Command Line Tools must be granted. If not you will be prompted like so:

<img src="Azure%20Active%20Directory/docs/Screenshot%202025-07-30%20135129.png" alt="Not enough permissions" width="300" height="500"/>

---
### `grant_consent_MSGraph.ps1` (Must be granted access to MS Graph!)

The provided script automates a delegated‐consent grant of Microsoft Graph permissions to a user on behalf of an application. In essence, it:
- Connects to Microsoft Graph with elevated scopes.
- Ensures a service principal exists for the client app (Graph Explorer).
- Creates an OAuth2 delegated permission grant for that app to call Microsoft Graph APIs as the specified user.
- Assigns the app to the user so it’s visible in their My Apps portal.

An illicit consent grant attack abuses this exact flow. An attacker automates the creation of a malicious app, tricks a user into granting it high-risk scopes, and then uses those tokens to exfiltrate data—bypassing credentials and MFA entirely. By scripting consent grants at scale, adversaries can stealthily establish persistent backdoors.

---
### `sendmail.py`

Send email impersonations, need "Mail.Send" permissions.

Use like so:
`python .\sendmail.py`

---
### `domains2ipsipv4Only.ps1`

Given a list of domain will provide DNS info. I use it in combination with the domains in a tenant to get info on them (is it on wix, aws, etc..)

Use like so, first get domains from tenant:
`az rest --method GET --uri "https://graph.microsoft.com/v1.0/domains" --headers "Content-Type=application/json" --query "value[].{Name:id,IsVerified:isVerified,AuthType:authenticationType}" -o table > all_domains.txt`

Results piped to all_domains.txt which we will feed into the script like so:

`.\domains2ipsipv4Only.ps1 -InputPath all_domains.txt -OutputPath ips.txt`

---
### `enum_entra_admins.ps1 & find_disabled_ad_accounts.ps1`

enum_entra_admins.ps1 will look at Entra groups with "administrator" as a display name. 
Then it will try to find users of that group, and output data to AdminLikeAccounts_Report.csv

find_disabled_ad_accounts.ps1 will read that input file AdminLikeAccounts_Report.csv and try to determine if any of these admins is "disabled".
It will produce a spreadsheet file named DisabledAccounts_Report.csv
Admins should investigate these files and clean up their AD/AAD as needed.

---
**list_all_applications2.ps1 & .BulkMultiPermExploitability2ps1 & Profile-App.ps1 & Audit-AppDelegationRisks.ps1**

### `list_all_applications2.ps1`
- **Purpose:** Enumerates every registered application and service principal in an Entra ID tenant.  
- **Use Case:** Provides a broad **inventory baseline** of all apps.  
- **Frequency:** Run **monthly or quarterly** as part of regular inventory checks.  

### `BulkMultiPermExploitability2.ps1`
- **Purpose:** Bulk‑checks each app for exploitable Microsoft Graph permissions against a defined high‑risk list.  
- **Use Case:** Ideal for **tenant‑wide risk sweeps** and permission audits.  
- **Frequency:** Run **monthly or quarterly** alongside inventory scans.  

### `Profile-App.ps1`
- **Purpose:** Profiles a single AppId in detail.  
- **Output Includes:** Owners, credentials, delegated/app‑only permissions, assignments, and recent sign‑ins.  
- **Use Case:** Produces a **governance‑ready profile** for documentation, incident response, or app reviews.  
- **Frequency:** Run **ad‑hoc** during investigations, risk reviews, or onboarding/offboarding of third‑party apps.  

### `Audit-AppDelegationRisks.ps1`
- **Purpose:** Focuses on delegated OAuth2 grants.  
- **Use Case:** Flags **tenant‑wide consents** with risky scopes and resolves who can access the app.  
- **Frequency:** Run **ad‑hoc** when reviewing suspicious or high‑risk apps.  

All scripts rely on the **[Microsoft.Graph PowerShell SDK](https://learn.microsoft.com/powershell/microsoftgraph/overview)**  
Before running the scripts, establish a Graph session with sufficient rights:
Use like so:

`.\list_all_applications2.ps1` Generates CSV files

`.\BulkMultiPermExploitability.ps1 -ScopeCsvPath ScopeBreakdown.csv` This parses previously generated CSV file

When you see "Problem!" this is how you dig deeper into the app details

`.\Profile-App.ps1 -TargetAppId dddddd-ba25-43c7-a710-cxxxx` 

`.\Audit-AppDelegationRisks.ps1 -TargetAppId dddddd-ba25-43c7-a710-cxxxx`



## ── 📂 Section: On-Prem Active Directory ──
---
### `ad_object_permissions3.ps1`

Audits Active Directory permissions for a given user and all the groups they belong to, within a specified LDAP container. It reports every Access Control Entry (ACE) that grants the user or their groups any rights on objects under the search base.

Use like so:
`.\ad_object_permissions3.ps1 -Username "XXX\mcontestabile" -Domain "DC=YYYYYY,DC=net"`

Each row in the output indicates a single permission grant:
- ObjectDN
The exact AD container or object that holds the ACE.
- Principal
Either the user account or one of their groups.
- Rights
The bitwise rights 

Keep an eye out for anything that shows 
 GenericAll or FullControl (Grants the user or group unrestricted rights over objects in sensitive OUs)
 WriteProperty or DeleteChild (Rights that allow modifying critical attributes (password resets, group membership) or removing child objects (users, computers))

---
### `delegated_rights.ps1`

Audits explicit ACLs for a single account under a given AD container. It dumps every Access Control Entry (ACE) on objects beneath your search base where the ACE’s IdentityReference exactly matches the provided username.

Use like so:
`.\delegated_rights.ps1 -Username "XXX\mcontestabile" -Domain "DC=YYYYYY,DC=net"`

---
### `servers_get_smb.ps1`

Discovers every domain-joined Windows Server via Active Directory, then remotely enumerates each server’s SMB shares and their share-level permissions.

---
### `gpo_delegation_check2.ps1`

Audits Group Policy Object (GPO) permissions across your Active Directory domain, focusing on the key delegation levels you care about: read, edit, and full‐control.
- If you see a trustee listed under GpoAll, they can fully manage that GPO—critically important for change control.
- GpoEdit entries indicate who can modify policy settings.
- GpoRead entries tell you who can view but not alter a GPO.

---
### `whois_islocal_admin2.ps1`

Lists members of the local Administrators group on the machine where the script runs.

---
### `check_blank_password_users.ps1`

Tests AD accounts for blank or username-equal passwords and reports results.

Use like so:
`.\check_blank_password_users.ps1 -DomainFqdn domain.net`

---
### `check_PSSession_blank_passwords2.ps1`

Tests whether AD accounts can open a PSSession with a blank password. A PSSession is a persistent, interactive PowerShell connection to a remote computer. It’s conceptually similar to a remote desktop session in that you have a “window” into the target machine—but it’s strictly text-based. You get a live PowerShell prompt on the remote host, not its full GUI desktop.

---
### `check_smb_settings_all_domain_joined_pc_using_ps_remoting.ps1`

For each domain joined computer, use WinRM to check SMB settings. 

---
### `check_smb_settings_all_domain_joined_pc_using_wmi_and_remote_registry.ps1`

For each domain joined computer, use WMI to check SMB settings.

---
### `inactive_users.ps1`

Finds enabled Active Directory users inactive for a specified number of days (default: 180), excluding the built-in Administrator account.

Use like so:
`.\inactive_users.ps1`

---
### `is_ldap_signing_enabled.ps1` (Requires PS version 7)

Supply values for the following parameters:
LdapServer: xxx.yyy.net
UserUPN: mcontestabile@yyy.net
Password: *************

---
### `replicate_permissions.ps1`

Audits permissions on an Active Directory user object.
- Accepts a SamAccountName as a parameter.
- Looks up the user’s DistinguishedName in AD.
- Retrieves the object’s Access Control List (ACL).
- Filters ACL entries to find where that same user (XXX\<UserSamAccountName>) has ExtendedRight privileges.
- Outputs a table showing who holds the right, what object type it applies to, the kind of rights, and whether it’s Allow or Deny.
Use this to verify special delegation or extended rights granted to a user against their own AD object.

Use like so:
`.\replicate_permissions.ps1 -UserName "XXX\yyy"`

`.\replicate_permissions.ps1 -UserName "mario@xxx.net"`

---
### `replicated_rights2.ps1`

Scans Active Directory objects under a specified subtree and reports any entries that grant a particular user elevated permissions.
Identifies which AD objects include access control entries (ACEs) granting the target account any of the following rights:
- GenericAll
- WriteProperty
- ExtendedRight

Use like so:
`.\replicated_rights2.ps1 -UserAccountName 'XXX\krbtgt' -SearchBase 'DC=xxx,DC=yyy' -Verbose`

---
### `setNoPreauth.ps1`

Provides a controlled way to disable Kerberos pre-authentication for an Active Directory user by flipping a single bit in their userAccountControl attribute. It also gives you clear visibility into which flags are set on that user object both before and after the change. Modifying the userAccountControl attribute in Active Directory isn’t something a standard domain user can do by default. You'll get "Exception calling "SetInfo" with "0" argument(s): "Access is denied."

Use like so:
`.\setNoPreauth.ps1 "LDAP://CN=Mario Contestabile,OU=blahblah,OU=bloop,DC=xxx,DC=yyy"`

---
### `AD_Audit_Script.ps1`

This uses PowerSploit. Ergo better to use in PowerShell 5.1 (just run powershell.exe -Version 5.1).
Creates a report file for you.

---
### `GpoAclAudit.ps1` (Requires PowerView!)

Audit powerful rights over GPOs. Inactive accounts are shown in red.

Use like so:
`.\GpoAclAudit.ps1 -DomainName xxx.net`

---
### `GetUsersAndTheirManagedByMachines.ps1`

Will generate a spreadsheet (AD-UserComputer-Audit.csv) for all users in your AD with computer they manage.

---
### `test_shares_read_write.ps1` (Requires PowerView!)

Given the output from:
`Invoke-ShareFinder | Export-Csv .\shared_folders.csv -NoTypeInformation`

This script will read the file "shared_folders.csv" and generate "ShareSecurityReport.csv".

Good targets to examine further on your AD are those shares shown as "DISK" and Readble is "TRUE"

---
### `analyze_gpo3.ps1`

Tries get gather info on the GPO's pushed to your machuine.
Loads the GPResult XML from disk
Gets GUIDS
For each extracted GUID, Builds the folder name, if found, scans subfolders for
 - registry.pol (machine)
 - Software installation XMLs 
 - Startup/Logon script
 - Preference XMLs
 - If the GroupPolicy module is loaded, Generates a temporary XML report
 - Build Consolidated Output Object

Step 1: Run `gpresult /x C:\Temp\gpresult.xml /SCOPE COMPUTER`
Step 2: Run `.\analyze_gpo3.ps1 -GPResultXml C:\Temp\gpresult.xml -SysvolRoot "\\your.domain.here\SYSVOL\domain.net\Policies"`

You will see good output. YOu can get additional details by running:

`Get-GPOReport -Id XXX -ReportType XML`

with the GUIDS produced at step 2.

---
### `lan_audit_full2.ps1`

This is a great tool to uncover secrets on a LAN. Corporations unknowingly share files. Developers unknowingly leave files behind. This script will:
1. Go over each file in the folder and subfolder
2. If it is a spreadsheet or Word or PDF document it will open those as well
3. It will search files for known secret values such as
      1. AWS Access Keys
      2. GitHub Tokens
      3. Private Keys
      4. Etc...a whole lot more

Use like:
`.\lan_audit_full2.ps1 "\\somedc.somedomain.net\UNCName\Any Folders" audit_report.csv`

---
## ── 📂 Section: Generic Directory ──
---
### `Test-Feeds3.ps1`

Run this script to validate network filtering, from the machine it is run on.
 
It uses 3 feeds updated daily:<br>
1- https://urlhaus.abuse.ch/api/#csv<br>
2- https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt<br>
3- https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt<br>
 
URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.
OpenPhish receives URLs from multiple streams and analyzes them using its proprietary phishing detection algorithms.
IPsum is a threat intelligence feed based on 30+ different publicly available lists of suspicious and/or malicious IP addresses. All lists are automatically retrieved and parsed on a daily (24h) basis and the final result is pushed to this repository. List is made of IP addresses together with a total number of (black)list occurrence (for each).

Run this from where we have some "security filtering" in place and get a good idea if the machine is protected! Enjoy!
 
(Run with -Quick to just do 25 lines)

---
### `Base64Tool.ps1`

Use like so:

`.\Base64Tool.ps1 -InputString 'SGVsbG8gV29ybGQh'`

(Equivalent to `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABlAGwAbABvACAAVwBvAHIAbABkACEA'))`)

`.\Base64Tool.ps1 -InputString 'Hello World!' -Encode`

(Equivalent to `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Hello World!'))`)
