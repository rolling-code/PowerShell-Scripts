
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
