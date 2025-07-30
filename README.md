
PowerShell-Scripts

A collection of PowerShell scripts for various administrative tasks, including Azure Active Directory and On-Prem Active Directory management.

Folder Structure:

```
PowerShell-Scripts/
├── Azure Active Directory/
│   └── get_az_token.ps1
│   └── aadinternals_audit6.ps1
├── On-Prem Active Directory/
│   └── ad_object_permissions3.ps1
│   └── delegated_rights.ps1
│   └── servers_get_smb.ps1
│   └── gpo_delegation_check2.ps1
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
**ad_object_permissions3.ps1**

Audits Active Directory permissions for a given user and all the groups they belong to, within a specified LDAP container. It reports every Access Control Entry (ACE) that grants the user or their groups any rights on objects under the search base.

Use like so:
.\ad_object_permissions3.ps1 -Username "XXX\mcontestabile" -Domain "DC=YYYYYY,DC=net"

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
**delegated_rights.ps1**

Audits explicit ACLs for a single account under a given AD container. It dumps every Access Control Entry (ACE) on objects beneath your search base where the ACE’s IdentityReference exactly matches the provided username.

Use like so:
.\delegated_rights.ps1 -Username "XXX\mcontestabile" -Domain "DC=YYYYYY,DC=net"

---
**servers_get_smb.ps1**

Discovers every domain-joined Windows Server via Active Directory, then remotely enumerates each server’s SMB shares and their share-level permissions.

---
**gpo_delegation_check2.ps1**

Audits Group Policy Object (GPO) permissions across your Active Directory domain, focusing on the key delegation levels you care about: read, edit, and full‐control.
- If you see a trustee listed under GpoAll, they can fully manage that GPO—critically important for change control.
- GpoEdit entries indicate who can modify policy settings.
- GpoRead entries tell you who can view but not alter a GPO.
