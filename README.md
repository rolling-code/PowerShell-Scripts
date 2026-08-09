
PowerShell-Scripts

A collection of PowerShell scripts (And some Python 🐍 as well) for various administrative tasks, including Azure Active Directory and On-Prem Active Directory management.

Folder Structure:

```
PowerShell-Scripts/
## ── 📂 ├── generic/
│   └── Base64Tool.ps1
│   └── Test-Feeds3.ps1
│   └── domains2ipsipv4Only.ps1
│   └── DisableWindowsDefender.ps1
│   └── kickoff.ps1
│   └── SetAdaptorMetricWired_Highest.ps1
│   └── Check-ModularDS.ps1
│   └── crt_enum.ps1
│   └── rmm_nrpt_block.ps1

## ── 📂 ├── Azure Active Directory/
│   └── get_az_token.ps1
│   └── aadinternals_audit6.ps1 (Uses AADInternals)
│   └── get_policies.ps1
│   └── grant_consent_MSGraph.ps1
│   └── sendmail.py
│   └── Check-AllPowerfulAzurePerms3.ps1
│   └── enum_entra_admins.ps1
│   └── find_disabled_accounts.ps1
│   └── Watch-AzAutomationRunbookJob.ps1
│   └── Audit-AllUsersRolePerms.ps1
│   └── Get-DisabledUsersLicenses.ps1
│   └── RemoveM365LicensesfromDisabledUsers.ps1
│   └── Inspect-AzWebAppSecurity-Consolidated.ps1
│   └── Audit-NeverSucceedingMailForwardingRules.ps1
│   └── Review-TeamsLifecycleCleanupCandidates.ps1
│   └── Report-InactiveGuestUsers-150Days.ps1
│   └── Get-AzureStorageAnonymousAccess.ps1
│   └── Test-AzureBlobAnonymousEndpoints.ps1
│   └── Test-EntraTokenProtectionPolicies.ps1
│   └── 👉** Azure AD application auditing tools **
        list_all_applications.ps1
        BulkMultiPermExploitability.ps1
        Profile-App.ps1
        Audit-AppDelegationRisks.ps1
│   └── 👉** automate creation of malicious-looking OAuth authorization flows (device‑code and consent URLs) used in consent‑phishing simulations **
│       New-MultiTenantOAuthConsentTrainingUrl.ps1
│       New-OAuthRedirectMismatchTrainingUrl.ps1
│       New-OrgOnlyOAuthConsentTrainingUrl.ps1

## ── 📂 ├── On-Prem Active Directory/
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
│   └── CheckWritableAttributesADUsers.py (Python, PowerShell version is below)
│   └── CheckWritableAttributesADUsers.ps1 (is the PowerShell equivalent of Python file above)
│   └── Test-ADDnsLowPrivWrite.ps1

## ── 📂 ├── MSADPT/
│   └── MSADPT_start2.ps1
│   └── MSADPT_enumerate_dc2.ps1
│   └── MSADPT_enumerate_shares2.ps1
│   └── MSADPT_scan_network2.ps1
│   └── MSADPT_audit_adcs_esc1_esc16.ps1
│   └── MSADPT_M365_DirectOAuth_ContentGrabber_V2.ps1
└── README.md
```

Usage:

1. Clone the repository:
   git clone https://github.com/rolling-code/PowerShell-Scripts.git
   I recommend professional pen testers also:
   git clone https://github.com/PowerShellMafia/PowerSploit.git
   and run ./kickoff.ps1
   - This script will setup many necessary modules.
   - This script will update these modules if you choose to do so.
   - This script will setup PowerSploit for you if run under PowerShell 5.1 (git clone that repo as shown above) 

3. Navigate to the desired folder, eg:
   cd "PowerShell-Scripts/Azure Active Directory"

4. Run the script using PowerShell, or Python eg:
   .\get_az_token.ps1

You may need modules to be loaded for some scripts to run properly. No worries I got you.
Run the script kickoff.ps1 to configure your powershell with all the necessary prerequisites.

Notes:

- Scripts are organized by domain (e.g., Azure AD, On-Prem AD).
- Contributions and suggestions are welcome!

## ── 📂 Section: Azure Active Directory ──
---
### `Check-AllPowerfulAzurePerms3.ps1`
A series of insightful articles on cloud permissions was recently published by Sonrai Security:
https://sonraisecurity.com/blog/powerful-cloud-permissions-you-should-know-part-1/

I gathered all the Azure permissions they highlighted and wrote a PowerShell script to validate them in my environment. Automating these checks enables the operations team (validates the current user’s permissions) to:
- Validate issues consistently
- Reproduce findings on demand
- Schedule regular cybersecurity health assessments

---
### `get_az_token.ps1`

ROPC Authentication Control Validation
This controlled test evaluates whether a specifically authorized Microsoft Entra public-client application can obtain a token for a designated test account through the Resource Owner Password Credentials flow. Because ROPC cannot perform interactive authentication or satisfy an MFA challenge, a response such as AADSTS50076 confirms that the applicable sign-in requires MFA and blocks the legacy password-only flow.
A successful token response indicates that the tested user, client application, resource and sign-in context were permitted to authenticate using username and password without completing MFA at the time of the test. It does not prove that Conditional Access is absent globally or that all users and applications have the same behavior. Microsoft has deprecated ROPC because it requires direct handling of user passwords and is incompatible with MFA, passwordless authentication and modern interactive controls.

**Sign-in error** code `50076` in Azure AD **indicates that MFA (Multi-Factor Authentication) is required**.

Notice the PowerShell user agent given we are using API calls from PS
![Notice the PowerShell user agent](Azure%20Active%20Directory/docs/image-20250514-202526.png)

Notice the MFA requirement error description, as expected.
![Notice the MFA requirement](Azure%20Active%20Directory/docs/image-20250514-202748.png)

```powershell
.\get_az_token.ps1 -TenantId "xxx" -Username "you@foo.bar" -ClientId "yyy" -AcknowledgeAuthorizedTesting
```

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

Performs a read-only analysis of the user-assignment scope for Microsoft Entra Conditional Access policies. The script resolves direct and transitive group memberships, active supported directory roles, policy inclusions and exclusions, and policy state, then explains why each policy targets, excludes, or does not target the specified user.
The script does not calculate whether every policy will trigger during a specific authentication attempt. Conditional Access runtime conditions such as cloud application, device compliance, platform, location, user or sign-in risk, client type, and authentication flow require the Conditional Access What If tool or sign-in-log evidence.

```powershell
.\get_policies.ps1 -UserPrincipalName "foo@contoso.com" -OutputCsv ".\ConditionalAccessUserTargeting.csv"
```

Microsoft Graph Command Line Tools must be granted. If not you will be prompted like so:

<img src="Azure%20Active%20Directory/docs/Screenshot%202025-07-30%20135129.png" alt="Not enough permissions" width="300" height="500"/>

---
### `grant_consent_MSGraph.ps1` (Must be granted access to MS Graph!)

Demonstrates how a privileged Microsoft Graph administrator can programmatically create a user-specific delegated permission grant between a client service principal and Microsoft Graph, then assign the client application to the selected user. The delegated grant authorizes the application to call Microsoft Graph on behalf of that user, subject to the granted scopes and the user’s own effective permissions.
This administrative workflow illustrates one mechanism that can be abused after a highly privileged identity or application is compromised. The script does not create a malicious application, perform consent phishing, obtain tokens, or independently bypass MFA. Because it modifies tenant consent and application assignments using highly privileged Graph permissions, it should be used only in an isolated lab or explicitly authorized administrative workflow.

```powershell
.\grant_consent_MSGraph.ps1  -ClientAppId "11111111-1111-1111-1111-111111111111"

.\grant_consent_MSGraph.ps1 -UserPrincipalName "alice@contoso.com"
```


---
### `sendmail.py`

Sends an authorized email through Microsoft Graph using app-only client-credentials authentication and the Mail.Send application permission. The script accepts configurable sender, recipient, subject, and message-body values, reads the application secret from an environment variable, supports a dry-run mode, and returns detailed Microsoft Graph errors without printing or storing access tokens.
The Entra application must have the Microsoft Graph Mail.Send application permission with administrator consent. Because this permission can provide broad mail-sending capability, Exchange Online App RBAC should be used to restrict the application to approved sender mailboxes. An HTTP 202 Accepted response confirms that Microsoft Graph accepted the message for processing, but does not guarantee final delivery.

```powershell
$secureSecret = Read-Host "Enter the application client secret" -AsSecureString

$env:ENTRA_CLIENT_SECRET = [System.Net.NetworkCredential]::new(
    "",
    $secureSecret
).Password

python .\send_graph_mail.py 
    --tenant-id "00000000-0000-0000-0000-000000000000" 
    --client-id "11111111-1111-1111-1111-111111111111" 
    --sender "notifications@contoso.com" 
    --recipient "analyst@contoso.com" 
    --subject "Microsoft Graph mail validation" 
    --body "This is an authorized app-only Microsoft Graph email test." 
    --acknowledge-authorized-mailbox 
    --dry-run
```
Send the message by removing --dry-run

---
### `Get-AzureStorageAnonymousAccess.ps1`

This read-only script audits Azure Storage accounts across all subscriptions accessible to the signed-in user. It uses Azure Resource Manager to inspect account settings and container ACLs, classifies effective anonymous access, and exports account-level and container-level CSV reports without requesting storage keys, generating SAS tokens, or changing resources.

---
### `Test-AzureBlobAnonymousEndpoints.ps1`

This script consumes the container CSV generated by Get-AzureStorageAnonymousAccess.ps1 and performs unauthenticated curl.exe tests against each applicable Blob container. It checks anonymous container enumeration and can optionally validate exact-object access using a one-byte range request when the CSV contains an ExactBlobName column.

```powershell
.\Test-AzureBlobAnonymousEndpoints.ps1 -InputCsv "C:\Users\mario\StorageContainerPublicAccessDetails-20260730-003512.csv"
```


---
### `enum_entra_admins.ps1 `

Searches Microsoft Entra for groups whose display names match a configurable administrator-like pattern and exports their direct and nested user members to AdminLikeAccounts_Report.csv. The report includes each user’s current Entra account status and hybrid synchronization attributes, but the naming match is a discovery signal and does not by itself prove that a group grants privileged access.
By default, the script searches for group names containing administrator and resolves membership transitively, including users inherited through nested groups.

---
### `find_disabled_accounts.ps1`

Reads any CSV containing Microsoft Entra user principal names or object IDs and checks whether each unique account is enabled or disabled in Entra ID. The script automatically detects common identity-column names, exports disabled accounts to DisabledAccounts_Report.csv, and can optionally produce a complete report containing enabled, disabled, unresolved, and failed lookups.
The script queries Microsoft Graph and therefore does not require a corporate network, VPN, domain controller, RSAT, or the on-premises Active Directory PowerShell module

```powershell
.\find_disabled_accounts.ps1 -CsvPath ".\accounts.csv"
```


---
### `Get-DisabledUsersLicenses.ps1`

Scans Microsoft Entra ID for disabled users who still have assigned Microsoft licenses and resolves license SKU identifiers into readable product names. The script exports one row per user-license assignment, distinguishes direct licensing from group-based licensing, identifies the assigning group, and records assignment state and errors.
An optional per-user summary consolidates each disabled account’s licenses and assignment methods for easier license-reclamation review. The script is completely read-only and does not modify users, groups, or license assignments.

```powershell
.\Get-DisabledUsersLicenses6.ps1 
    -ExportCsv ".\DisabledUserLicenseDetails.csv" 
    -SummaryCsv ".\DisabledUserLicenseSummary.csv"
```

---
### `RemoveM365LicensesfromDisabledUsers.ps1`

Audits disabled Microsoft Entra users with effective license assignments and exports detailed license-source and action-summary reports. The script distinguishes directly assigned licenses from group-based licensing and operates in audit-only mode by default. Direct licenses can be removed only through the explicit -Execute switch, with support for approved-user CSV input, targeted UPNs, -WhatIf, confirmation prompts, and detailed action logging. Reuses the current Microsoft Graph PowerShell session and does not request new consent automatically.

Audit Mode
```powershell
# Reuse an existing Microsoft Graph session.
Connect-MgGraph -Scopes "User.Read.All", "Organization.Read.All" -NoWelcome

# Audit all disabled licensed member accounts.
# No licenses are removed.
.\RemoveM365LicensesfromDisabledUsers.ps1
```

Removal Mode
```powershell
# Reuse an existing Microsoft Graph session with license-management permission.
Connect-MgGraph -Scopes "User.Read.All", "Organization.Read.All", "LicenseAssignment.ReadWrite.All" -NoWelcome

# Preview the removal of directly assigned licenses from users
# listed in a reviewed CSV. No licenses are removed with -WhatIf.
.\RemoveM365LicensesfromDisabledUsers.ps1 `
    -ApprovedUsersCsv ".\approved-users.csv" `
    -Execute `
    -WhatIf

# After reviewing the preview, remove -WhatIf to execute.
.\RemoveM365LicensesfromDisabledUsers.ps1 `
    -ApprovedUsersCsv ".\approved-users.csv" `
    -Execute
```



---
👉** Azure AD application auditing tools **

### `list_all_applications.ps1`
Enumerates all Microsoft Entra application registrations and enterprise application service principals visible to the current Microsoft Graph session. Exports separate application and service-principal reports, plus a normalized combined CSV inventory. Reuses an existing Graph session by default and supports optional interactive connection using Application.Read.All.

The three scripts now have separated purposes:

**BulkMultiPermExploitability.ps1**
Finds high-risk application and delegated permissions across the inventory.

**Profile-App.ps1**
Creates a complete governance profile for one application.

**Audit-AppDelegationRisks.ps1**
Performs a focused delegated-consent risk assessment for one application.


### `BulkMultiPermExploitability.ps1`
BulkMultiPermExploitability.ps1 reviews Microsoft Entra applications for granted Microsoft Graph permissions that match a configurable high-risk permission catalog.
The script evaluates both:

Application permissions, represented by app-role assignments
Delegated permissions, represented by OAuth2 permission grants

It accepts an application inventory CSV produced by list_all_applications.ps1, using the ApplicationClientId column to correlate application registrations with their tenant service principals.
The script is read-only. It reuses the current Microsoft Graph PowerShell session, does not request consent, does not modify application permissions, and does not disconnect the existing session.

The recommended input is generated by: list_all_applications.ps1
The recommended input for this permission review is: entra-application-registrations-YYYYMMDD-HHMMSS.csv
```powershell
.\BulkMultiPermExploitability.ps1 
    -InputCsvPath ".\entra-application-registrations-20260730-175924.csv"
```


### `Profile-App.ps1`
- **Purpose:** Profiles a single AppId in detail.  
Creates a governance-ready profile for a single Microsoft Entra application using its application client ID.
Output includes:
Application registration and service principal metadata, owners, password and certificate credential metadata, application permissions, delegated OAuth consent grants, enterprise application assignments, interactive sign-ins, service principal sign-ins, and data-availability warnings.
Run ad hoc when investigating findings from BulkMultiPermExploitability.ps1, reviewing a privileged integration, validating an application owner, or assessing an application before remediation.
```powershell
.\Profile-App.ps1 -TargetAppId "xxx"
```

### `Audit-AppDelegationRisks.ps1`
Audits delegated OAuth consent grants for a single Microsoft Entra application, expands each granted scope into an individual record, and identifies high-impact delegated permissions using a built-in or caller-supplied risk catalog.

Identifies tenant-wide AllPrincipals consent, privileged delegated scopes, missing ownership, and principals assigned to access an enterprise application. Intended for evidence-driven application reviews, consent investigations, and least-privilege validation.

Run ad hoc when investigating suspicious applications, validating findings from BulkMultiPermExploitability.ps1, or reviewing privileged third-party integrations.

```powershell
.\list_all_applications.ps1 //Generates CSV files

.\BulkMultiPermExploitability.ps1 -ScopeCsvPath ScopeBreakdown.csv //This parses previously generated CSV file
```

```powershell
.\Profile-App.ps1 -TargetAppId dddddd-ba25-43c7-a710-cxxxx

.\Audit-AppDelegationRisks.ps1 -TargetAppId dddddd-ba25-43c7-a710-cxxxx
```

### `Audit-AllUsersRolePerms.ps1`

Performs a tenant-wide, read-only audit of Microsoft Entra default user permissions, active directory-role assignments, and high-privilege Azure RBAC access. Expands role-assignable and Azure RBAC groups into effective user privilege paths, distinguishes direct from group-derived assignments, and generates timestamped findings, evidence, coverage, warning, and governance reports.

```powershell
.\Audit-AllUsersRolePerms.ps1
```

---
👉 **OAuth consent and application trust awareness demonstrations**

These scripts generate controlled Microsoft Entra OAuth authorization URLs for authorized security-awareness training and application-trust validation.

Together, they demonstrate three distinct scenarios:

- An organization-only application registered in the user's tenant
- An intentionally invalid redirect URI rejected by Microsoft Entra
- A multi-tenant application that can present a consent request across organizational boundaries

The scripts construct authorization URLs only. They do not create or modify application registrations, deliver links, open browsers, exchange authorization codes, acquire tokens, or access user data.

Application Registration and Redirect URI Requirements

The GitHub Pages examples can be opened immediately to preview the user-facing simulation pages. However, previewing a page is not the same as completing its OAuth flow.

For the OAuth flows that reach GitHub Pages, a real application registration and an exact registered redirect URI are mandatory. The application and the GitHub Pages URL are therefore intertwined:

The application must be registered in the simulation administrator’s own tenant.
OAuth parameters such as the client ID must come from that application registration.
The corresponding GitHub Pages callback URL must be entered as an authorized redirect URI on that same application.
The redirect URI supplied during authorization must exactly match the registered value.
Reusing another organization’s client ID or copying only the example URL will not produce a functional OAuth flow.


## Application Registration, Redirect URI, and Page Relationship

For the OAuth flows that reach GitHub Pages, a real application registration and an exact registered redirect URI are mandatory. The application registration, client ID, tenant, authorization URL, and GitHub Pages callback URL must be configured as one matching set.

| Component | Required configuration | Relationship to the application and URL | Preview or validation |
|---|---|---|---|
| Application registration | Create an application **registered in the user's own tenant**, meaning a tenant where the authorized tester or simulation administrator can create and configure applications. | The application provides the client ID used by the OAuth authorization request. Copying the generic examples does not create or register this application automatically. | Confirm that the application appears under **Microsoft Entra ID > App registrations** in the tenant used for the authorized simulation. |
| Tenant context | Use a tenant controlled by the authorized tester or simulation administrator. The application must be **registered in one tenant** before its client ID can be used in the OAuth flow. | The tenant determines where the application exists, which identity provider processes the request, and which application configuration is evaluated. | Confirm that the tenant used in the authorization URL is the tenant where the application was registered. |
| Client ID | Replace the generic client ID placeholder with the Application (client) ID generated for the newly registered application. | The client ID identifies the application whose redirect URI configuration Microsoft Entra ID will validate. A client ID copied from an example or another organization is not interchangeable with an application registered in the operator's tenant. | Compare the client ID in the generated authorization URL with the Application (client) ID shown in the application's Overview page. |
| Registered redirect URI | Add `https://rolling-code.github.io/PowerShell-Scripts/oauth-training-success.html` as a redirect URI on the same application identified by the client ID. | The redirect URI supplied in the OAuth request must exactly match the URI registered on that application. The application and URL are therefore directly intertwined. | Confirm that the complete URL, including `https://`, capitalization, path, filename, and `.html` extension, exactly matches the redirect URI configured on the application. |
| GitHub Pages callback page | The simulation uses `https://rolling-code.github.io/PowerShell-Scripts/oauth-training-success.html` as its GitHub Pages destination. | This page is the destination reached after the identity provider processes the request. Publishing or opening the page does not automatically create the required application registration. | **[OPEN THIS URL](https://rolling-code.github.io/PowerShell-Scripts/oauth-training-success.html)** to preview what the page will look like once the application is created and correctly configured. |
| OAuth authorization URL | The applicable PowerShell script constructs the authorization URL by combining the tenant context, client ID, requested permissions, and registered GitHub Pages redirect URI. | All values must belong to the same authorized simulation. Changing the client ID, tenant, or callback URL without updating the corresponding application registration breaks the relationship. | Inspect the generated authorization URL and verify that its client ID and redirect URI match the application registration. |
| Direct page preview | The GitHub Pages URL may be opened directly before creating the application. | Direct access is a **visual preview only**. It shows what the destination page will look like, but it does not validate the application, create an OAuth request, grant permissions, or complete an OAuth flow. | **[OPEN THIS URL TO PREVIEW THE PAGE](https://rolling-code.github.io/PowerShell-Scripts/oauth-training-success.html)** |
| Complete authorized simulation | Combine an application **registered in the user's own tenant**, its actual client ID, the correct tenant context, and the exact registered GitHub Pages redirect URI. | This is not a simple copy-and-paste operation. The application and callback URL must be intentionally configured together by the authorized tester or simulation administrator. | Complete the simulation only after confirming that the client ID, tenant, redirect URI, GitHub Pages URL, and relevant script parameters all refer to the same configured application. |

### `New-MultiTenantOAuthConsentTrainingUrl.ps1`

Generates a constrained Microsoft identity platform authorization URL for an operator-owned, multi-tenant Microsoft Entra application.
 
The scenario demonstrates how an application registered in one tenant can present a Microsoft-hosted sign-in and consent request to users in another organization. It emphasizes the importance of validating the application publisher, tenant context, requested permissions, and expected business purpose.
 
The application and redirect URI must already be configured by the authorized operator. The script does not create or modify application registrations, deliver the URL, open a browser, exchange authorization codes, acquire tokens, or access user data.

```powershell
.\New-MultiTenantOAuthConsentTrainingUrl.ps1 `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -Authority "organizations" `
    -RedirectUri "https://rolling-code.github.io/PowerShell-Scripts/oauth-training-multitenant.html" `
    -CopyToClipboard `
    -AcknowledgeAuthorizedTraining
```

---
### `New-OAuthRedirectMismatchTrainingUrl.ps1`

Generates an OAuth authorization URL containing an intentionally unregistered redirect URI to demonstrate Microsoft Entra redirect URI validation. 

The expected result is an `AADSTS50011` error from Microsoft Entra. This teaches that a familiar application name or genuine Microsoft-hosted sign-in page cannot override the redirect URIs registered on an application. 

The demonstration requires an application registration owned by the operator or explicitly authorized for testing. It does not use a Microsoft-owned client ID, modify the application, acquire tokens, or redirect to a custom training page.

```powershell
.\New-OAuthRedirectMismatchTrainingUrl.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -IntentionallyUnregisteredRedirectUri "https://example.invalid/not-registered" `
    -CopyToClipboard `
    -AcknowledgeAuthorizedTraining
```

---
### `New-OrgOnlyOAuthConsentTrainingUrl.ps1`

Generates a constrained, tenant-specific Microsoft identity platform authorization URL for an organization-only OAuth consent-awareness demonstration. 

The scenario shows how an application registered in the user's own Microsoft Entra tenant can present a genuine Microsoft consent screen. It teaches participants to validate the application publisher, requested permissions, and expected business purpose rather than trusting the sign-in page or application name alone. 

The application and redirect URI must already be configured by the authorized operator. The script does not create or modify the application registration, deliver the URL, open a browser, exchange authorization codes, acquire tokens, or access user data.

```powershell
.\New-OrgOnlyOAuthConsentTrainingUrl.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -RedirectUri "https://rolling-code.github.io/PowerShell-Scripts/oauth-training-success.html" `
    -CopyToClipboard `
    -AcknowledgeAuthorizedTraining
```

---
#### Watch-AzAutomationRunbookJob.ps1

Monitors an existing Azure Automation runbook job, periodically reports its current state, and displays newly available Output, Verbose, Warning, Error, or Progress stream records until the job reaches a terminal state.

The script can monitor a supplied job ID or automatically select the most recent job for a specified runbook. It reuses the current Azure PowerShell context by default and does not start, stop, suspend, or modify Azure Automation jobs.

Monitor the latest runbook job
```powershell
.\Watch-AzAutomationRunbookJob.ps1 `
    -ResourceGroupName "rg-automation" `
    -AutomationAccountName "aa-security-operations" `
    -RunbookName "Invoke-SecurityValidation"
```
Monitor a specific job and all streams
```powershell
.\Watch-AzAutomationRunbookJob.ps1 `
    -ResourceGroupName "rg-automation" `
    -AutomationAccountName "aa-security-operations" `
    -RunbookName "Invoke-SecurityValidation" `
    -JobId "00000000-0000-0000-0000-000000000000" `
    -Streams Any `
    -PollSeconds 10
```
Permit interactive authentication when required
```powershell
.\Watch-AzAutomationRunbookJob.ps1 `
    -ResourceGroupName "rg-automation" `
    -AutomationAccountName "aa-security-operations" `
    -RunbookName "Invoke-SecurityValidation" `
    -AllowInteractiveLogin
```

---
### `Inspect-AzWebAppSecurity-Consolidated.ps1`
Will check Web app for things like:
- Outbound IPs
- Hostnames
- Publishing Profiles
- TLS
- Secrets
- Key Vault
- Defender
- WAF etc...

```powershell
.\Inspect-AzWebAppSecurity-Consolidated.ps1 -SubscriptionId xxx -ResourceGroup "yyy" -AppName "zzz"
```

---
### `Audit-NeverSucceedingMailForwardingRules.ps1`

Audits Exchange Online mailbox forwarding and Inbox rules for deterministic “will not succeed” or cleanup-worthy conditions.

This script checks user and shared mailboxes for Exchange Online mailbox-level forwarding and Inbox rules that are stale, disabled, expired, or reference recipients that no longer resolve. It is intended to produce CSV evidence for mailbox rule cleanup, Secure Score remediation, and Exchange hygiene user stories.

It checks for things like:

- Mailbox-level forwarding to unresolved recipients
- Inbox rules that forward, redirect, or forward as attachment to unresolved recipients
- Rules pointing to soft-deleted, legacyDN, GUID, or missing Exchange recipients
- Expired Inbox rule date conditions that should no longer match future mail
- Disabled Inbox rules, when `-IncludeDisabledRules` is used
- External forwarding that would be blocked by the tenant outbound forwarding policy, when `-IncludePolicyBlockedExternalForwarding` is used
- Inbox rule warning messages, when `-IncludeReviewWarnings` is used

Useful for identifying stale mailbox rules, broken forwarding logic, and forwarding-related exfiltration risk. Microsoft documents that Inbox rules can forward or redirect mailbox messages, and Microsoft also warns that automatic forwarding can be abused after account compromise for data disclosure/exfiltration.

```powershell
.\Audit-NeverSucceedingMailForwardingRules.ps1 -OutputDirectory . -IncludeReviewWarnings
```

---
### `Review-TeamsLifecycleCleanupCandidates.ps1`

Performs a read-only Microsoft Teams lifecycle hygiene review.

Will check Teams-backed Microsoft 365 groups for things like:

- Teams with no members
- Teams with no enabled/active members
- Teams with disabled members present
- Teams with external/guest members
- Teams with no owners
- Teams with no enabled/active owners
- Teams with excessive owners based on a configurable threshold

This script is useful for identifying stale, orphaned, or risky Teams that may need owner validation, membership cleanup, archiving, or deletion review.

The script does **not** delete, archive, or modify any Teams.

```powershell
.\Review-TeamsLifecycleCleanupCandidates.ps1
```

---
### `Report-InactiveGuestUsers-150Days.ps1`

Creates a read-only report of Microsoft Entra guest users who have been inactive for more than a defined number of days.

By default, the script reports guest users inactive for more than **150 days** and exports the results to CSV, sorted from oldest sign-in to newest sign-in.

Will check Microsoft Entra guest users for things like:

- Guest account display name
- Guest user principal name
- Mail address
- Account enabled/disabled state
- External user state
- Created date
- Last successful sign-in date
- Last interactive sign-in date
- Last non-interactive sign-in date
- Effective last sign-in date
- Days since last sign-in
- Inactivity reason
- Recommended action
- Object ID

Guests with no sign-in date are included as **Never signed in** if the guest account was created before the inactivity threshold.

This script is useful for reviewing stale B2B/guest accounts before disabling or removing access.

The script does **not** block, delete, or modify users.

```powershell
.\Report-InactiveGuestUsers-150Days.ps1
```

---
### `Test-EntraTokenProtectionPolicies.ps1`

Read-only PowerShell audit script that retrieves Microsoft Entra Conditional Access policies through an existing Azure CLI session and evaluates whether Token Protection is configured.

The script identifies:

Native Token Protection for supported Windows applications accessing Exchange Online, SharePoint Online, Microsoft Teams, Azure Virtual Desktop, or Windows 365.
Browser-based Token Protection Preview for supported web applications accessing Azure Resource Manager.
Policies with enabled but incomplete or nonstandard Token Protection targeting.
Conditional Access policies without Token Protection.

```powershell
.\Test-EntraTokenProtectionPolicies.ps1
```




## ── 📂 Section: On-Prem Active Directory ──
---
### `Get-AdPrincipalPermissions.ps1`

Audits Active Directory ACEs that apply to a user through direct and nested security-group membership beneath a specified LDAP search base. Reports effective principals, rights, inheritance, scoped object types, and risk context, with optional CSV export for further review.

```powershell
.\Get-AdPrincipalPermissions.ps1 -Username "XXX\mcontestabile" -Domain "DC=YYYYYY,DC=net"
```

## Understanding the output

Each output row represents one matching Access Control Entry associated with the target user or one of the user's direct or nested security groups.

### Key fields

- **ObjectDN:** Distinguished name of the AD object whose security descriptor contains the ACE.
- **ObjectClass:** Type of AD object, such as a user, group, organizational unit, computer, or Group Policy container.
- **Principal:** Target user or group to which the ACE applies.
- **PrincipalType:** Whether the matching principal is the user or an AD security group.
- **Rights:** Active Directory rights recorded in the ACE.
- **AccessControlType:** Indicates whether the ACE allows or denies the listed rights.
- **IsInherited:** Indicates whether the ACE is explicit on the object or inherited from a parent.
- **ObjectType:** Attribute, object class, property set, or extended right scoped by the ACE.
- **RiskSeverity / RiskReason:** Triage guidance generated by the script. These fields assist review but do not replace validation of the affected object and scoped right.

## Rights that warrant closer review

Prioritize ACEs containing:

- **GenericAll:** Full control over the affected AD object.
- **GenericWrite:** Broad ability to modify writable properties.
- **WriteDacl:** Ability to change the object's permissions and potentially grant additional access.
- **WriteOwner:** Ability to assume ownership and potentially alter permissions.
- **WriteProperty:** Ability to modify one or more attributes. Impact depends on the attribute or property set shown in `ObjectType`.
- **ExtendedRight:** A scoped control right whose impact depends on `ObjectType`. Some extended rights are sensitive, while others, such as **Apply Group Policy**, are expected and low risk.
- **CreateChild / DeleteChild:** Ability to create or remove specific child-object types beneath a container or OU.
- **Delete / DeleteTree:** Ability to delete an object or an object subtree.

Always evaluate:

1. The affected object in `ObjectDN`
2. Whether the ACE is explicit or inherited
3. The granting principal
4. The scoped attribute, class, or extended right in `ObjectType`
5. Whether the permission is required for the principal's documented function

---
### `delegated_rights.ps1`

Audits explicit ACLs for a single account under a given AD container. It dumps every Access Control Entry (ACE) on objects beneath your search base where the ACE’s IdentityReference exactly matches the provided username.

```powershell
.\delegated_rights.ps1 -Username "XXX\mcontestabile" -Domain "DC=YYYYYY,DC=net"
```

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

```powershell
.\check_blank_password_users.ps1 -DomainFqdn domain.net
```

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

```powershell
.\inactive_users.ps1
```

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

```powershell
.\replicate_permissions.ps1 -UserName "XXX\yyy"
```
```powershell
.\replicate_permissions.ps1 -UserName "mario@xxx.net"
```

---
### `replicated_rights2.ps1`

Scans Active Directory objects under a specified subtree and reports any entries that grant a particular user elevated permissions.
Identifies which AD objects include access control entries (ACEs) granting the target account any of the following rights:
- GenericAll
- WriteProperty
- ExtendedRight

```powershell
.\replicated_rights2.ps1 -UserAccountName 'XXX\krbtgt' -SearchBase 'DC=xxx,DC=yyy' -Verbose
```

---
### `setNoPreauth.ps1`

Provides a controlled way to disable Kerberos pre-authentication for an Active Directory user by flipping a single bit in their userAccountControl attribute. It also gives you clear visibility into which flags are set on that user object both before and after the change. Modifying the userAccountControl attribute in Active Directory isn’t something a standard domain user can do by default. You'll get "Exception calling "SetInfo" with "0" argument(s): "Access is denied."

```powershell
.\setNoPreauth.ps1 "LDAP://CN=Mario Contestabile,OU=blahblah,OU=bloop,DC=xxx,DC=yyy"
```

---
### `AD_Audit_Script.ps1` (Requires PowerSploit! Ergo better to use in PowerShell 5.1 (just run powershell.exe -Version 5.1).)

Creates a report file for you.

---
### `GpoAclAudit.ps1` (Requires PowerSploit! Ergo better to use in PowerShell 5.1 (just run powershell.exe -Version 5.1).)

Audit powerful rights over GPOs. Inactive accounts are shown in red.

```powershell
.\GpoAclAudit.ps1 -DomainName xxx.net
```

---
### `GetUsersAndTheirManagedByMachines.ps1`

Will generate a spreadsheet (AD-UserComputer-Audit.csv) for all users in your AD with computer they manage.

---
### `test_shares_read_write.ps1` 

Given the output from the PowerSploit:
`Invoke-ShareFinder | Export-Csv .\shared_folders.csv -NoTypeInformation`

This script will read the file "shared_folders.csv" and generate "ShareSecurityReport.csv".

Good targets to examine further on your AD are those shares shown as "DISK" and Readble is "TRUE"

---
### `analyze_gpo3.ps1`

Gathers info on the GPO's pushed to your machine.
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

You will see good output. You can get additional details by running:

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

```powershell
.\lan_audit_full2.ps1 "\\somedc.somedomain.net\UNCName\Any Folders" audit_report.csv
```

---
### `CheckWritableAttributesADUsers.py|.ps1`

The Python svcript uses strictly LDAP3 to enumerate the AD users (use the -dc-ip parameter to specify your Domain Controller IP).
Then it will attempt to write "temp" to attributes to determine if any is writeable.
Although not the most elegent solution - it works! It will write a users.cvs file, which should only contain your own AD account-any others are worhty of ivestigation!
```powershell
python3 CheckWritableAttributesADUsers.py DOMAIN/mcontestabile:'XXX' -dc-ip 1.2.3.4
```

The PowerShell version does the same thing - but with a twist.
Firstly, it will try to use ADWS first before falling back to LDAP.
Secondly, it also produces a ADUsers.csv output file but it contains the "WriteableAttributes" for each user. 
Users with excessive permissions will stand out!

Use with parameters and it will use your current Windows account. You can specify like so:
`-Dc 1.2.0.10 -Out investigate_UsersPS.csv`

or specify other creds like so:

`$cred = Get-Credential domain\otheruser
.\CheckWritableAttributesADUsers.ps1 -Credential $cred`

Use `-PageSize 200` for large directories.

---
### `Test-ADDnsLowPrivWrite.ps1`

Check if your AD is vulnerable to registering a DNS record in an Active Directory DNS zone.
https://www.depthsecurity.com/blog/using-ntlm-reflection-to-own-active-directory/

Usage:
`\Test-ADDnsLowPrivWrite.ps1 -DcHost dc.xxx.net -Verbose`

`\Test-ADDnsLowPrivWrite.ps1 -DcHost dc.xxx.net -UseSSL -Port 636 -Zone xxx.net -Verbose`

`\Test-ADDnsLowPrivWrite.ps1 -DcHost dc.xxx.net -UseSSL -Port 636 -DomainNC 'DC=xxx,DC=net' -Verbose`

You can verify via ADWS in case of output: "[FAIL] VULNERABLE: low-priv add succeeded (record created)."

`
$zoneDn  = 'DC=xxx.net,CN=MicrosoftDNS,CN=System,DC=foo,DC=net'

$label   = '_aclvtest-XXX' <= Change this

$server  = 'dc.xxx.net'

Get-ADObject  -Server $server  -LDAPFilter "(dc=$label)"   -SearchBase $zoneDn -SearchScope Subtree  -Properties dc,dnsRecord,whenCreated,whenChanged,distinguishedName | Format-List distinguishedName,dc,whenCreated,whenChanged


distinguishedName : DC=_aclvtest-XXX,DC=xxx.net,CN=MicrosoftDNS,CN=System,DC=foo,DC=net

dc                : _aclvtest-XXX

whenCreated       : 1/19/2026 12:56:35 PM

whenChanged       : 1/19/2026 12:56:35 PM

`

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

```powershell
.\Base64Tool.ps1 -InputString 'SGVsbG8gV29ybGQh'
```

Equivalent to 
```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABlAGwAbABvACAAVwBvAHIAbABkACEA'))
.\Base64Tool.ps1 -InputString 'Hello World!' -Encode
```
Equivalent to 
```powershell
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Hello World!'))
```

---
### `domains2ipsipv4Only.ps1`

Given a list of domain will provide DNS info. I use it in combination with the domains in a tenant to get info on them (is it on wix, aws, etc..)

First get domains from tenant:
```powershell
az rest --method GET --uri "https://graph.microsoft.com/v1.0/domains" --headers "Content-Type=application/json" --query "value[].{Name:id,IsVerified:isVerified,AuthType:authenticationType}" -o table > all_domains.txt
```
Results piped to all_domains.txt which we will feed into the script like so:
```powershell
.\domains2ipsipv4Only.ps1 -InputPath all_domains.txt -OutputPath ips.txt
```

---
### `DisableWindowsDefender.ps1`

Disables Windows Defender Services. Need to run as admin.

If you want to automatically do so after every reboot & login event, run this PowerSHell to create a Scheduled Task which will run that .ps1 for you under SYSTEM.
```powershell
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\mcontestabile\DisableWindowsDefender.ps1"'
$Triggers = @(
  New-ScheduledTaskTrigger -AtStartup
  New-ScheduledTaskTrigger -AtLogOn
)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "Git-PostLogonScript" -Action $Action -Trigger $Triggers -Principal $Principal -Description "Run post-logon script elevated"
```

---
### `SetAdaptorMetricWired_Highest.ps1`

Set interface metrics for physical adapters only.
- Disconnected physical adapters => metric 100
- Connected physical adapters => metric 10 (except when both wired+wifi are Up: wired=10, wifi=50) Like the name says, prefer wired over wifi
- Use -Trial to preview planned changes without applying them

Use like so to see what changes it will perform without applying them:
```powershell
.\SetAdaptorMetricWired_Highest.ps1 -Trial
```

---
### `Check-ModularDS.ps1`

Check if a WordPress web site is vulnerable to: CVE-2026-23550
https://modulards.com/a-note-on-the-recent-modular-ds-security-update/

---
### `crt_enum.ps1`

Performs automated subdomain discovery and service enumeration by ingesting a CSV file and extracting domain names specifically from the Asset Name column, then querying the certificate transparency database at crt.sh using its JSON endpoint (https://crt.sh/?q=<domain>&output=json) with a 30-second timeout and up to 3 retries per domain to ensure reliability against transient failures. For each input domain, it parses all returned certificate entries, extracts and normalizes unique domain names (including handling wildcard certificates and multi-value fields), and identifies newly discovered subdomains. It then sequentially tests network reachability via TCP connection attempts (3-second timeout) on ports 80 (HTTP), 443 (HTTPS), 22 (SSH), and 3389 (RDP), and, when web services are available, performs HTTP(S) requests to retrieve page titles for basic fingerprinting.

---
### `rmm_nrpt_block.ps1`

Add local Windows NRPT-based RMM domain block script generated from the LOLRMM domain list (https://lolrmm.io/api/rmm_domains.csv).
NRPTUsage: run PowerShell as Administrator, then execute 

`.\rmm_nrpt_block.ps1`

to create local RMMBlockTest NRPT rules.NRPT (Name Resolution Policy Table) lets Windows apply DNS resolution rules for domain namespaces/suffixes before normal DNS lookup, making it better suited than a hosts file for wildcard-style domains like *.teamviewer.com or *.anydesk.com.
Removal: run 

`.\rmm_nrpt_block.ps1 -Remove`

to delete only the NRPT rules created by this script.

Chosen over hosts file because hosts only supports exact hostnames, while NRPT supports broader namespace/suffix blocking for local testing.
To verify rule run:

`Get-DnsClientNrptRule | Where-Object Comment -eq 'RMMBlockTest'`

---
### `lookup.ps1`

Download KEV JSON 

`Invoke-WebRequest -Uri "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" -OutFile kev.json`

Download EPSS CSV 

`Invoke-WebRequest -Uri "https://epss.cyentia.com/epss_scores-current.csv.gz" -OutFile epss.gz`

Populate table with your CVEs

```powershell
[PSCustomObject]@{ 
        Asset = "foo - Edge Browser" 
        CVE   = "CVE-2026-7902" 
    }, 
```
Run lookup.ps1

## ── 📂 Section: MSADPT ──
---

### `MSADPT_start2.ps1`
This script requires all input to be provided through command-line parameters.

It uses the supplied domain credential, target domain FQDN, and bootstrap Active Directory server to collect environment, Domain Controller, and ADCS discovery information.

The results are written to CSV output files.

---

## Mandatory Parameter Summary

| Parameter | Mandatory | Type | Description |
|---|---:|---|---|
| `-Credential` | Yes | `PSCredential` | Domain credential used for Active Directory enumeration operations. Typically supplied using `(Get-Credential)`. |
| `-DomainFQDN` | Yes | `string` | Fully qualified domain name to enumerate. Example: `foo.bar`. |
| `-AdServer` | Yes | `string` | Bootstrap Domain Controller or ADWS-capable server used to perform the initial Active Directory queries. Example: `DC1.foo.bar`. |
| `-EnvironmentOutputCsvPath` | Yes | `string` | CSV output path for environment details collected by the script. |
| `-DCOutputCsvPath` | Yes | `string` | CSV output path for discovered Domain Controllers. |
| `-ADCSOutputCsvPath` | Yes | `string` | CSV output path for discovered Active Directory Certificate Services servers. |

---

## Input Parameters

> These are runtime values supplied to the script.  
> No input files are required by this script.

| Parameter | Classification | Example |
|---|---|---|
| `-Credential` | 🟧 **INPUT VALUE** | `(Get-Credential)` |
| `-DomainFQDN` | 🟧 **INPUT VALUE** | `foo.bar` |
| `-AdServer` | 🟧 **INPUT VALUE** | `DC1.foo.bar` |

---

## Output Files

| Parameter | Classification | Example Output File |
|---|---|---|
| `-EnvironmentOutputCsvPath` | 🟩 **OUTPUT FILE** | `C:\temp\MSADPT_Output\MSADPT_Environment_20260427.csv` |
| `-DCOutputCsvPath` | 🟩 **OUTPUT FILE** | `C:\temp\MSADPT_Output\MSADPT_DCs_20260427.csv` |
| `-ADCSOutputCsvPath` | 🟩 **OUTPUT FILE** | `C:\temp\MSADPT_Output\MSADPT_ADCS_20260427.csv` |

---

## Example Usage

```powershell
.\MSADPT_start2.ps1 -Credential (Get-Credential) `
    -DomainFQDN "foo.bar" `
    -EnvironmentOutputCsvPath "C:\temp\MSADPT_Output\MSADPT_Environment_20260427.csv" `
    -DCOutputCsvPath "C:\temp\MSADPT_Output\MSADPT_DCs_20260427.csv" `
    -ADCSOutputCsvPath "C:\temp\MSADPT_Output\MSADPT_ADCS_20260427.csv" `
    -AdServer "DC1.foo.bar"
```

### `MSADPT_enumerate_dc2.ps1`

This script enumerates details from Domain Controllers that were previously discovered by the MSADPT discovery/start script.

It reads a Domain Controller CSV file as input, connects to Active Directory using explicit credentials, targets an explicitly supplied ADWS-capable Domain Controller, and writes per-DC enumeration output to a specified output directory.

The script does not assume that the host running it is domain joined.

---

## Mandatory Parameter Summary

| Parameter | Mandatory | Type | Description |
|---|---:|---|---|
| `-InputDcCsvPath` | Yes | `string` | Path to the input CSV file containing discovered Domain Controllers. The file must exist before the script runs. |
| `-OutputBaseDir` | Yes | `string` | Base directory where per-DC output folders and CSV files will be written. |
| `-Credential` | Yes | `PSCredential` | Domain credential used for all Active Directory enumeration operations. Typically supplied using `(Get-Credential)`. |
| `-DomainFQDN` | Yes | `string` | Fully qualified domain name to enumerate. Example: `foo.bar`. |
| `-AdServer` | Yes | `string` | Domain Controller or ADWS-capable server used for all Active Directory queries. Example: `DC1.foo.bar`. |

---

## Input Files and Input Values

> These are files or runtime values required by the script.

| Parameter / Item | Classification | Example |
|---|---|---|
| `-InputDcCsvPath` | 🟧 **INPUT FILE** | `C:\temp\MSADPT_Output\MSADPT_DCs.csv` |
| `MSADPT.Helpers.psm1` | 🟧 **REQUIRED LOCAL DEPENDENCY FILE** | `.\MSADPT.Helpers.psm1` |
| `-Credential` | 🟧 **INPUT VALUE** | `(Get-Credential)` |
| `-DomainFQDN` | 🟧 **INPUT VALUE** | `foo.bar` |
| `-AdServer` | 🟧 **INPUT VALUE** | `DC1.foo.bar` |

---

## Output Location

| Parameter | Classification | Example Output Location |
|---|---|---|
| `-OutputBaseDir` | 🟩 **OUTPUT DIRECTORY** | `C:\temp\MSADPT_Output\DC_Enumeration` |

---

## Example Usage

```powershell
.\MSADPT_enumerate_dc2.ps1 `
    -InputDcCsvPath "C:\temp\MSADPT_Output\MSADPT_DCs.csv" `
    -OutputBaseDir "C:\temp\MSADPT_Output\DC_Enumeration" `
    -Credential (Get-Credential) `
    -DomainFQDN "foo.bar" `
    -AdServer "DC1.foo.bar"
```

### `MSADPT_enumerate_shares2.ps1`

This script enumerates network shares on previously discovered Domain Controllers and prepares per-DC output locations for share enumeration results.

It consumes a Domain Controller CSV file generated by a previous MSADPT discovery script, uses explicit domain credentials for operations, and writes output under a specified base directory.

The script does not assume that the host running it is domain joined.

---

## Mandatory Parameter Summary

| Parameter | Mandatory | Type | Description |
|---|---:|---|---|
| `-InputDcCsvPath` | Yes | `string` | Path to the input CSV file containing discovered Domain Controllers. The file must exist before the script runs. |
| `-OutputBaseDir` | Yes | `string` | Base output directory where per-DC share enumeration output folders and files will be written. |
| `-Credential` | Yes | `PSCredential` | Domain credential used for Active Directory and share enumeration operations. Typically supplied using `(Get-Credential)`. |

---

## Input Files and Input Values

> These are files or runtime values required by the script.

| Parameter / Item | Classification | Example |
|---|---|---|
| `-InputDcCsvPath` | 🟧 **INPUT FILE** | `C:\temp\MSADPT_Output\MSADPT_DCs.csv` |
| `MSADPT.Helpers.psm1` | 🟧 **REQUIRED LOCAL DEPENDENCY FILE** | `.\MSADPT.Helpers.psm1` |
| `-Credential` | 🟧 **INPUT VALUE** | `(Get-Credential)` |

---

## Output Location

| Parameter | Classification | Example Output Location |
|---|---|---|
| `-OutputBaseDir` | 🟩 **OUTPUT DIRECTORY** | `C:\temp\MSADPT_Output\Shares` |

---

## Example Usage

```powershell
.\MSADPT_enumerate_shares2.ps1 `
    -InputDcCsvPath "C:\temp\MSADPT_Output\MSADPT_DCs.csv" `
    -OutputBaseDir "C:\temp\MSADPT_Output\Shares" `
    -Credential (Get-Credential)
```

### `MSADPT_scan_network2.ps1`

This script performs explicit network discovery and service checks against one or more operator-supplied IPv4 target ranges.

It does not automatically derive local network ranges, does not assume the host is domain joined, and does not rely on a configuration file or session-scoped credentials.

The script can optionally attempt to use `nmap` if it is available in `PATH`, and can optionally perform SMB signing checks depending on the supplied parameter values.

---

## Mandatory Parameter Summary

| Parameter | Mandatory | Type | Description |
|---|---:|---|---|
| `-Credential` | Yes | `PSCredential` | Credential used for remote operations that require authentication. Typically supplied using `(Get-Credential)`. |
| `-NetworkRanges` | Yes | `string[]` | One or more explicit IPv4 target ranges to process. Supports CIDR ranges and start/end IP ranges. |
| `-CommonPorts` | Yes | `int[]` | One or more TCP ports to check. Ports must be between `1` and `65535`. |
| `-UseNmapIfAvailable` | Yes | `bool` | Indicates whether the script should attempt to use `nmap` if it is present in `PATH`. |
| `-CheckSMBSigning` | Yes | `bool` | Indicates whether SMB signing checks should be performed in the main scan logic. |
| `-OutputBaseDir` | Yes | `string` | Base directory for any per-run or raw output artifacts. |
| `-OutputHostsCsvPath` | Yes | `string` | Explicit CSV output path for discovered hosts. |
| `-OutputOpenPortsCsvPath` | Yes | `string` | Explicit CSV output path for discovered open ports. |
| `-OutputSmbSigningCsvPath` | Yes | `string` | Explicit CSV output path for SMB signing results. |

---

## Input Files and Input Values

> These are files, dependencies, or runtime values required by the script.

| Parameter / Item | Classification | Example |
|---|---|---|
| `MSADPT.Helpers.psm1` | 🟧 **REQUIRED LOCAL DEPENDENCY FILE** | `.\MSADPT.Helpers.psm1` |
| `-Credential` | 🟧 **INPUT VALUE** | `(Get-Credential)` |
| `-NetworkRanges` | 🟧 **INPUT VALUE** | `"10.10.10.0/24","10.20.30.10-10.20.30.20"` |
| `-CommonPorts` | 🟧 **INPUT VALUE** | `445,3389,5985` |
| `-UseNmapIfAvailable` | 🟧 **INPUT VALUE** | `$true` |
| `-CheckSMBSigning` | 🟧 **INPUT VALUE** | `$true` |

---

## Output Locations and Files

| Parameter | Classification | Example Output Location |
|---|---|---|
| `-OutputBaseDir` | 🟩 **OUTPUT DIRECTORY** | `C:\temp\MSADPT_Output\Network` |
| `-OutputHostsCsvPath` | 🟩 **OUTPUT FILE** | `C:\temp\MSADPT_Output\MSADPT_Network_Hosts.csv` |
| `-OutputOpenPortsCsvPath` | 🟩 **OUTPUT FILE** | `C:\temp\MSADPT_Output\MSADPT_OpenPorts.csv` |
| `-OutputSmbSigningCsvPath` | 🟩 **OUTPUT FILE** | `C:\temp\MSADPT_Output\MSADPT_SMBSigning_Status.csv` |

---

## Example Usage

```powershell
.\MSADPT_scan_network2.ps1 `
    -Credential (Get-Credential) `
    -NetworkRanges "10.10.10.0/24","10.20.30.10-10.20.30.20" `
    -CommonPorts 445,3389,5985 `
    -UseNmapIfAvailable $true `
    -CheckSMBSigning $true `
    -OutputBaseDir "C:\temp\MSADPT_Output\Network" `
    -OutputHostsCsvPath "C:\temp\MSADPT_Output\MSADPT_Network_Hosts.csv" `
    -OutputOpenPortsCsvPath "C:\temp\MSADPT_Output\MSADPT_OpenPorts.csv" `
    -OutputSmbSigningCsvPath "C:\temp\MSADPT_Output\MSADPT_SMBSigning_Status.csv"
```

### `MSADPT_audit_adcs_esc1_esc16.ps1`

This script performs a defensive, configuration-focused audit of an Active Directory Certificate Services (AD CS) deployment for likely exposure indicators associated with ESC1 through ESC16.

The script enumerates enterprise Certification Authorities, published certificate templates, PKI-related objects in the Configuration partition, template ACLs, selected PKI object ACLs, selected CA registry flags, selected Domain Controller certificate-mapping posture indicators, and web enrollment exposure indicators where possible.

The script does not exploit anything, request or forge certificates, or modify templates, ACLs, registry keys, or CA settings.

---

## Mandatory Parameter Summary

| Parameter | Mandatory | Type | Description |
|---|---:|---|---|
| `-OutputBaseDir` | Yes | `string` | Directory where CSV and log outputs are written. |
| `-IncludeUnpublishedTemplates` | Yes | `switch` | Controls whether all certificate templates in Active Directory are evaluated. When omitted behavior is not allowed because the parameter is mandatory. Use `-IncludeUnpublishedTemplates` to enable, or `-IncludeUnpublishedTemplates:$false` to disable. |
| `-SkipRemoteChecks` | Yes | `switch` | Controls whether best-effort remote registry and web endpoint checks against CA servers and Domain Controllers are skipped. Use `-SkipRemoteChecks` to skip remote checks, or `-SkipRemoteChecks:$false` to perform them. |
| `-DirectoryServer` | Yes | `string` | Domain Controller or directory server to use for Active Directory queries. Example: `DC1.foo.bar`. |
| `-Credential` | Yes | `PSCredential` | Credential used for Active Directory queries and remote checks. Typically supplied using `(Get-Credential)` or a credential variable. |

---

## Input Files and Input Values

> These are files, dependencies, switches, or runtime values required by the script.

| Parameter / Item | Classification | Example |
|---|---|---|
| `MSADPT.Helpers.psm1` | 🟧 **REQUIRED LOCAL DEPENDENCY FILE** | `.\MSADPT.Helpers.psm1` |
| `-DirectoryServer` | 🟧 **INPUT VALUE** | `DC1.foo.bar` |
| `-Credential` | 🟧 **INPUT VALUE** | `$cred` |
| `-IncludeUnpublishedTemplates` | 🟧 **INPUT SWITCH** | `-IncludeUnpublishedTemplates:$false` |
| `-SkipRemoteChecks` | 🟧 **INPUT SWITCH** | `-SkipRemoteChecks:$false` |

---

## Output Locations and Files

| Parameter / Output | Classification | Example |
|---|---|---|
| `-OutputBaseDir` | 🟩 **OUTPUT DIRECTORY** | `C:\temp\MSADPT_Output\ADCS` |
| `MSADPT_ADCS_ESC_Audit_<timestamp>.csv` | 🟩 **OUTPUT FILE** | `C:\temp\MSADPT_Output\ADCS\MSADPT_ADCS_ESC_Audit_<timestamp>.csv` |
| `MSADPT_ADCS_ESC_Audit_Log_<timestamp>.txt` | 🟩 **OUTPUT FILE** | `C:\temp\MSADPT_Output\ADCS\MSADPT_ADCS_ESC_Audit_Log_<timestamp>.txt` |

---

## Example Usage: Standard Audit

```powershell
$cred = Get-Credential

.\MSADPT_audit_adcs_esc1_esc16.ps1 `
    -DirectoryServer "DC1.foo.bar" `
    -Credential $cred `
    -OutputBaseDir "C:\temp\MSADPT_Output\ADCS" `
    -IncludeUnpublishedTemplates:$false `
    -SkipRemoteChecks:$false
```

### `MSADPT_M365_DirectOAuth_ContentGrabber_V2.ps1`

Add M365 Direct OAuth device-code validation helper for approved tabletop and lab scenarios.

This script demonstrates how Graph-scoped device-code authentication differs from Azure CLI / Az PowerShell management-context authentication, and records resulting M365 content-access indicators for defensive validation and awareness exercises.



