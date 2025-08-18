
PowerShell-Scripts

A collection of PowerShell scripts for various administrative tasks, including Azure Active Directory and On-Prem Active Directory management.

Folder Structure:

```
PowerShell-Scripts/
├── generic/
│   └── Base64Tool.ps1
├── Azure Active Directory/
│   └── get_az_token.ps1
│   └── aadinternals_audit6.ps1
│   └── get_policies.ps1
│   └── grant_consent_MSGraph.ps1
│   └── sendmail.py
├── On-Prem Active Directory/
│   └── ad_object_permissions3.ps1
│   └── delegated_rights.ps1
│   └── servers_get_smb.ps1
│   └── gpo_delegation_check2.ps1
│   └── whois_islocal_admin2.ps1
│   └── check_blank_password_users.ps1
│   └── check_PSSession_blank_passwords2.ps1
│   └── check_smb_settings_all_domain_joined_pc_using_ps_remoting.ps1
│   └── check_smb_settings_all_domain_joined_pc_using_wmi_and_remote_registry.ps1
│   └── inactive_users.ps1
│   └── is_ldap_signing_enabled.ps1
│   └── replicate_permissions.ps1
│   └── replicated_rights2.ps1
│   └── setNoPreauth.ps1
│   └── AD_Audit_Script.ps1
│   └── GpoAclAudit.ps1
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

---
**get_az_token.ps1**

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
**aadinternals_audit6.ps1**

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
**ad_object_permissions3.ps1** (Requires PowerView!)

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
**delegated_rights.ps1** (Requires PowerView!)

Audits explicit ACLs for a single account under a given AD container. It dumps every Access Control Entry (ACE) on objects beneath your search base where the ACE’s IdentityReference exactly matches the provided username.

Use like so:
`.\delegated_rights.ps1 -Username "XXX\mcontestabile" -Domain "DC=YYYYYY,DC=net"`

---
**servers_get_smb.ps1**

Discovers every domain-joined Windows Server via Active Directory, then remotely enumerates each server’s SMB shares and their share-level permissions.

---
**gpo_delegation_check2.ps1** (Requires PowerView!)

Audits Group Policy Object (GPO) permissions across your Active Directory domain, focusing on the key delegation levels you care about: read, edit, and full‐control.
- If you see a trustee listed under GpoAll, they can fully manage that GPO—critically important for change control.
- GpoEdit entries indicate who can modify policy settings.
- GpoRead entries tell you who can view but not alter a GPO.

---
**get_policies.ps1**

Determines which Azure AD Conditional Access (CA) policies apply to a specific user, evaluating both direct user inclusion/exclusion and group or role–based assignments.

Use like so:
`.\get_policies.ps1 userPrincipalname@domain.net`

NOTE: Microsoft Graph Command Line Tools must be granted.
If not you will be prompted like so ![Not enough permissions](Azure%20Active%20Directory/docs/Screenshot%202025-07-30%20135129.png)

---
**whois_islocal_admin2.ps1**

Lists members of the local Administrators group on the machine where the script runs.

---
**check_blank_password_users.ps1**

Tests AD accounts for blank or username-equal passwords and reports results.

Use like so:
`.\check_blank_password_users.ps1 -DomainFqdn domain.net`

---
**check_PSSession_blank_passwords2.ps1**

Tests whether AD accounts can open a PSSession with a blank password. A PSSession is a persistent, interactive PowerShell connection to a remote computer. It’s conceptually similar to a remote desktop session in that you have a “window” into the target machine—but it’s strictly text-based. You get a live PowerShell prompt on the remote host, not its full GUI desktop.

---
**check_smb_settings_all_domain_joined_pc_using_ps_remoting.ps1**

For each domain joined computer, use WinRM to check SMB settings. 

---
**check_smb_settings_all_domain_joined_pc_using_wmi_and_remote_registry.ps1**

For each domain joined computer, use WMI to check SMB settings.

---
**Base64Tool.ps1**

Use like so:

`.\Base64Tool.ps1 -InputString 'SGVsbG8gV29ybGQh'`

(Equivalent to `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABlAGwAbABvACAAVwBvAHIAbABkACEA'))`)

`.\Base64Tool.ps1 -InputString 'Hello World!' -Encode`

(Equivalent to `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Hello World!'))`)

---
**inactive_users.ps1**

Finds enabled Active Directory users inactive for a specified number of days (default: 180), excluding the built-in Administrator account.

Use like so:
`.\inactive_users.ps1`

---
**is_ldap_signing_enabled.ps1** (Requires PS version 7)

Supply values for the following parameters:
LdapServer: xxx.yyy.net
UserUPN: mcontestabile@yyy.net
Password: *************

---
**grant_consent_MSGraph.ps1**

The provided script automates a delegated‐consent grant of Microsoft Graph permissions to a user on behalf of an application. In essence, it:
- Connects to Microsoft Graph with elevated scopes.
- Ensures a service principal exists for the client app (Graph Explorer).
- Creates an OAuth2 delegated permission grant for that app to call Microsoft Graph APIs as the specified user.
- Assigns the app to the user so it’s visible in their My Apps portal.

An illicit consent grant attack abuses this exact flow. An attacker automates the creation of a malicious app, tricks a user into granting it high-risk scopes, and then uses those tokens to exfiltrate data—bypassing credentials and MFA entirely. By scripting consent grants at scale, adversaries can stealthily establish persistent backdoors.

---
**replicate_permissions.ps1** (Requires PowerView!)

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
**replicated_rights2.ps1** (Requires PowerView!)

Scans Active Directory objects under a specified subtree and reports any entries that grant a particular user elevated permissions.
Identifies which AD objects include access control entries (ACEs) granting the target account any of the following rights:
- GenericAll
- WriteProperty
- ExtendedRight

Use like so:
`.\replicated_rights2.ps1 -UserAccountName 'XXX\krbtgt' -SearchBase 'DC=xxx,DC=yyy' -Verbose`

---
**setNoPreauth.ps1**

Provides a controlled way to disable Kerberos pre-authentication for an Active Directory user by flipping a single bit in their userAccountControl attribute. It also gives you clear visibility into which flags are set on that user object both before and after the change. Modifying the userAccountControl attribute in Active Directory isn’t something a standard domain user can do by default. You'll get "Exception calling "SetInfo" with "0" argument(s): "Access is denied."

Use like so:
`.\setNoPreauth.ps1 "LDAP://CN=Mario Contestabile,OU=blahblah,OU=bloop,DC=xxx,DC=yyy"`

---
**AD_Audit_Script.ps1**

This uses PowerSploit. Ergo better to use in PowerShell 5.1 (just run powershell.exe -Version 5.1).
Creates a report file for you.

---
**GpoAclAudit.ps1** (Requires PowerView!)

Audit powerful rights over GPOs. Inactive accounts are shown in red.

Use like so:
`.\GpoAclAudit.ps1 -DomainName xxx.net`

---
**sendmail.py**

Send email impersonations, need "Mail.Send" permissions.

Use like so:
`python .\sendmail.py`
