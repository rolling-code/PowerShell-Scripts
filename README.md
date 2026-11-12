# PowerShell-Scripts
A collection of PowerShell scripts and Python 🐍 utilities for security validation, administration, reporting, Microsoft Entra ID, Azure, Microsoft 365, and on-premises Active Directory.

## Folder Structure

Entries with documentation in this README jump to the corresponding section below. Entries without a dedicated description open the source file directly.

- **PowerShell-Scripts/**
  - 📂 **[generic/](#section-generic-directory)**
    - [Base64Tool.ps1](#base64toolps1)
    - [Test-Feeds3.ps1](#test-feeds3ps1)
    - [Check-ArtexSetup-v1.1.0.ps1](#check-artexsetup-v110ps1)
    - [Start-ArtexWebAssessment-v1.1.0.ps1](#start-artexwebassessment-v110ps1)
    - [domains2ipsipv4Only.ps1](#domains2ipsipv4onlyps1)
    - [DisableWindowsDefender.ps1](#disablewindowsdefenderps1)
    - [kickoff.ps1](#kickoffps1)
    - [Invoke-CveRiskAssessment.ps1](#invoke-cveriskassessmentps1)
    - [SetAdaptorMetricWired_Highest.ps1](#setadaptormetricwired_highestps1)
    - [crt_enum.ps1](#crt_enumps1)
    - [generic/Set-DynamicNrptDomainBlock.ps1](#set-dynamicnrptdomainblockps1)
    - [WP-CVE-Validator.ps1](#wp-cve-validatorps1)
    - [SSH-CVE-Validator.ps1](#ssh-cve-validatorps1)
    - [Test-GitHubRepositorySecurity.ps1](#test-githubrepositorysecurityps1)
    - [Invoke-PythonRepositorySecurityScan.ps1](#invoke-pythonrepositorysecurityscanps1)
  - 📂 **[Azure Active Directory/](#section-azure-active-directory)**
    - [get_az_token.ps1](#get_az_tokenps1)
    - [aadinternals_audit6.ps1](#aadinternals_audit6ps1)
    - [get_policies.ps1](#get_policiesps1)
    - [grant_consent_MSGraph.ps1](#grant_consent_msgraphps1)
    - [sendmail.py](#sendmailpy)
    - [Check-AllPowerfulAzurePerms3.ps1](#check-allpowerfulazureperms3ps1)
    - [enum_entra_admins.ps1](#enum_entra_adminsps1)
    - [find_disabled_accounts.ps1](#find_disabled_accountsps1)
    - [Watch-AzAutomationRunbookJob.ps1](#watch-azautomationrunbookjobps1)
    - [Audit-AllUsersRolePerms.ps1](#audit-allusersrolepermsps1)
    - [Get-DisabledUsersLicenses.ps1](#get-disableduserslicensesps1)
    - [RemoveM365LicensesfromDisabledUsers.ps1](#removem365licensesfromdisabledusersps1)
    - [Inspect-AzWebAppSecurity-Consolidated.ps1](#inspect-azwebappsecurity-consolidatedps1)
    - [Audit-NeverSucceedingMailForwardingRules.ps1](#audit-neversucceedingmailforwardingrulesps1)
    - [Review-TeamsLifecycleCleanupCandidates.ps1](#review-teamslifecyclecleanupcandidatesps1)
    - [Report-InactiveGuestUsers-150Days.ps1](#report-inactiveguestusers-150daysps1)
    - [Get-AzureStorageAnonymousAccess.ps1](#get-azurestorageanonymousaccessps1)
    - [Test-AzureBlobAnonymousEndpoints.ps1](#test-azureblobanonymousendpointsps1)
    - [Test-EntraTokenProtectionPolicies.ps1](#test-entratokenprotectionpoliciesps1)
    - [Get-EntraApplicationGovernanceAssessment.ps1](#get-entraapplicationgovernanceassessmentps1)
    - [BulkMultiPermExploitability.ps1](#bulkmultipermexploitabilityps1)
    - [Profile-App.ps1](#profile-appps1)
    - [Audit-AppDelegationRisks.ps1](#audit-appdelegationrisksps1)
    - [New-MultiTenantOAuthConsentTrainingUrl.ps1](#new-multitenantoauthconsenttrainingurlps1)
    - [New-OAuthRedirectMismatchTrainingUrl.ps1](#new-oauthredirectmismatchtrainingurlps1)
    - [New-OrgOnlyOAuthConsentTrainingUrl.ps1](#new-orgonlyoauthconsenttrainingurlps1)
  - 📂 **[On-Prem Active Directory/](#section-on-prem-active-directory)**
    - [Get-AdPrincipalPermissions.ps1](#get-adprincipalpermissionsps1)
    - [delegated_rights.ps1](#delegated_rightsps1)
    - [servers_get_smb.ps1](#servers_get_smbps1)
    - [gpo_delegation_check2.ps1](#gpo_delegation_check2ps1)
    - [whois_islocal_admin2.ps1](#whois_islocal_admin2ps1)
    - [check_blank_password_users.ps1](#check_blank_password_usersps1)
    - [check_PSSession_blank_passwords2.ps1](#check_pssession_blank_passwords2ps1)
    - [check_smb_settings_all_domain_joined_pc_using_ps_remoting.ps1](#check_smb_settings_all_domain_joined_pc_using_ps_remotingps1)
    - [check_smb_settings_all_domain_joined_pc_using_wmi_and_remote_registry.ps1](#check_smb_settings_all_domain_joined_pc_using_wmi_and_remote_registryps1)
    - [inactive_users.ps1](#inactive_usersps1)
    - [is_ldap_signing_enabled.ps1](#is_ldap_signing_enabledps1)
    - [replicate_permissions.ps1](#replicate_permissionsps1)
    - [replicated_rights2.ps1](#replicated_rights2ps1)
    - [setNoPreauth.ps1](#setnopreauthps1)
    - [AD_Audit_Script.ps1](#ad_audit_scriptps1)
    - [GpoAclAudit.ps1](#gpoaclauditps1)
    - [GetUsersAndTheirManagedByMachines.ps1](#getusersandtheirmanagedbymachinesps1)
    - [test_shares_read_write.ps1](#test_shares_read_writeps1)
    - [analyze_gpo3.ps1](#analyze_gpo3ps1)
    - [lan_audit_full2.ps1](#lan_audit_full2ps1)
    - [CheckWritableAttributesADUsers.py](#checkwritableattributesaduserspyps1)
    - [CheckWritableAttributesADUsers.ps1](#checkwritableattributesaduserspyps1)
    - [Test-ADDnsLowPrivWrite.ps1](#test-addnslowprivwriteps1)

## Usage

Clone the repository:

```powershell
git clone https://github.com/rolling-code/PowerShell-Scripts.git
Set-Location .\PowerShell-Scripts
```

Some legacy scripts use PowerSploit. If a specific script requires it, clone PowerSploit separately:

```powershell
git clone https://github.com/PowerShellMafia/PowerSploit.git
```

Run `kickoff.ps1` from the repository root to install or update common prerequisites. PowerSploit setup requires Windows PowerShell 5.1 and a local PowerSploit clone.

```powershell
.\kickoff.ps1
```

Navigate to the relevant directory and run the desired script. For example:

```powershell
Set-Location '.\Azure Active Directory'
.\get_az_token.ps1
```

Review each script's comment-based help, parameters, prerequisites, and safety notes before execution. Use authorized test accounts and environments where a script performs active validation or makes changes.

## Notes

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
<a id="get_policiesps1"></a>

### `get_policies.ps1` (Must be granted access to MS Graph!)

Performs a read-only analysis of the user-assignment scope for Microsoft Entra Conditional Access policies. The script resolves direct and transitive group memberships, active supported directory roles, policy inclusions and exclusions, and policy state, then explains why each policy targets, excludes, or does not target the specified user.
The script does not calculate whether every policy will trigger during a specific authentication attempt. Conditional Access runtime conditions such as cloud application, device compliance, platform, location, user or sign-in risk, client type, and authentication flow require the Conditional Access What If tool or sign-in-log evidence.

```powershell
.\get_policies.ps1 -UserPrincipalName "foo@contoso.com" -OutputCsv ".\ConditionalAccessUserTargeting.csv"
```

Microsoft Graph Command Line Tools must be granted. If not you will be prompted like so:

<img src="Azure%20Active%20Directory/docs/Screenshot%202025-07-30%20135129.png" alt="Not enough permissions" width="300" height="500"/>

---
<a id="grant_consent_msgraphps1"></a>

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

python .\sendmail.py 
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
<a id="enum_entra_adminsps1"></a>

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

### `Get-EntraApplicationGovernanceAssessment.ps1`

Performs a read-only, evidence-driven Microsoft Entra application-governance assessment and exports a structured multi-sheet Excel workbook plus matching JSON evidence. The script centralizes application registrations, enterprise application service principals, ownership, owner account status, direct active Entra roles, application and delegated permissions, enterprise assignments, password and certificate metadata, App Instance Property Lock, publisher verification, multitenant posture, user-assignment requirements, workload sign-in activity where available, and conservative governance classifications.

The assessment reuses an existing Azure CLI Microsoft Graph token by default, displays the signed-in identity, tenant, OAuth client, granted authorization, current stage, pagination, and completion percentage, and performs only read operations. Alternative existing-Graph and interactive authentication modes are available where those clients already have suitable consent.

The generated workbook includes complete inventories for all collected application registrations and service principals, a normalized combined inventory, explicit inventory-parity checks, and separate worksheets for governance evidence and review leads. Classifications are intended for prioritization and follow-up validation; they do not treat every ownerless, old, multitenant, or credential-bearing application as a confirmed vulnerability.

Key worksheets include:
- **Application Inventory**: every collected application registration.
- **Service Principal Inventory**: every collected enterprise application service principal, including tenant-owned applications, external or multitenant applications, Microsoft-published applications, managed identities, legacy service principals, and other objects.
- **Combined Inventory**: normalized application-registration and service-principal inventory.
- **Owners** and **Owner Active Roles**: ownership and direct active Entra-role context.
- **All App Permissions** and **Graph App Permissions**: app-only permissions across resource APIs and the Microsoft Graph subset.
- **Delegated Grants** and **Enterprise Assignments**: delegated consent scopes and assigned users, groups, or service principals.
- **Credentials**, **Ownerless Apps**, **Old Applications**, and **Disabled With Grants**: governance review leads.
- **App Instance Lock**, **Publisher Verification**, **Multitenant Apps**, **Sign-In Activity**, **Classifications**, and **Errors**: hardening context, activity coverage, prioritized relationships, and collection limitations.

Requires PowerShell 7.2 or later, Microsoft.Graph.Authentication, ImportExcel, Azure CLI for the default authentication mode, and an already-authorized Microsoft Graph token with sufficient access. The script does not request new tenant consent automatically and does not modify applications, service principals, owners, credentials, permissions, grants, assignments, roles, or policies.

```powershell
Set-Location '.\Azure Active Directory'

.\Get-EntraApplicationGovernanceAssessment.ps1 `
    -AuthenticationMode AzureCLI `
    -TenantId '00000000-0000-0000-0000-000000000000'
```

Use a non-default age threshold for the **Old Applications** worksheet:

```powershell
.\Get-EntraApplicationGovernanceAssessment.ps1 `
    -AuthenticationMode AzureCLI `
    -TenantId '00000000-0000-0000-0000-000000000000' `
    -OldAppAgeDays 730
```

### `BulkMultiPermExploitability.ps1`
BulkMultiPermExploitability.ps1 reviews Microsoft Entra applications for granted Microsoft Graph permissions that match a configurable high-risk permission catalog.
The script evaluates both:

Application permissions, represented by app-role assignments
Delegated permissions, represented by OAuth2 permission grants

It accepts an application inventory CSV containing an ApplicationClientId column. Export the **Application Inventory** worksheet generated by Get-EntraApplicationGovernanceAssessment.ps1 to CSV when a focused revalidation workflow is needed.
The script is read-only. It reuses the current Microsoft Graph PowerShell session, does not request consent, does not modify application permissions, and does not disconnect the existing session.

The recommended input is generated by: Get-EntraApplicationGovernanceAssessment.ps1
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
.\Get-EntraApplicationGovernanceAssessment.ps1 -AuthenticationMode AzureCLI -TenantId "00000000-0000-0000-0000-000000000000"

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
<a id="get-appsecurityweeklydigest-v103ps1"></a>


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




## ── 📂 Section: On-Prem Active Directory ──
---
### `Get-AdPrincipalPermissions.ps1`

Audits Active Directory ACEs that apply to a user through direct and nested security-group membership beneath a specified LDAP search base. Reports effective principals, rights, inheritance, scoped object types, and risk context, with optional CSV export for further review.

```powershell
.\Get-AdPrincipalPermissions.ps1 -Username "XXX\analyst" -Domain "DC=YYYYYY,DC=net"
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
.\delegated_rights.ps1 -Username "XXX\analyst" -Domain "DC=YYYYYY,DC=net"
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
<a id="is_ldap_signing_enabledps1"></a>

### `is_ldap_signing_enabled.ps1` (Requires PS version 7)

Supply values for the following parameters:
LdapServer: xxx.yyy.net
UserUPN: analyst@yyy.net
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
.\setNoPreauth.ps1 "LDAP://CN=Example User,OU=blahblah,OU=bloop,DC=xxx,DC=yyy"
```

---
<a id="ad_audit_scriptps1"></a>

### `AD_Audit_Script.ps1` (Requires PowerSploit! Ergo better to use in PowerShell 5.1 (just run powershell.exe -Version 5.1).)

Creates a report file for you.

---
<a id="gpoaclauditps1"></a>

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

Good targets to examine further on your AD are those shares shown as "DISK" and Readable is "TRUE"

---
### `analyze_gpo3.ps1`

Gathers info on the GPO's pushed to your machine.
Loads the GPResult XML from disk
Gets GUIDs
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

with the GUIDs produced at step 2.

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

The Python script uses strictly LDAP3 to enumerate the AD users (use the -dc-ip parameter to specify your Domain Controller IP).
Then it will attempt to write "temp" to attributes to determine if any is writeable.
Although not the most elegent solution - it works! It will write a users.csv file, which should only contain your own AD account-any others are worthy of investigation!
```powershell
python3 CheckWritableAttributesADUsers.py DOMAIN/analyst:'XXX' -dc-ip 1.2.3.4
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
### `kickoff.ps1`

Configures common PowerShell prerequisites used by scripts in this repository. The script can install or update required modules and can set up PowerSploit when run from Windows PowerShell 5.1 after the PowerSploit repository has been cloned locally.

Run from the repository root:

```powershell
.\kickoff.ps1
```

---
### `Check-ArtexSetup-v1.1.0.ps1`

**Repository path:** `generic/Check-ArtexSetup-v1.1.0.ps1`  
**Current version:** 1.1.0  
Checks whether Docker Desktop and Ollama are installed and ready for a local ARTEX deployment. The script reports Git, Docker, Docker Compose, Ollama, LLM model, repository, branch, commit, container, and listener details. If ARTEX is not already present at the configured repository path, the script explains the expected location and asks before cloning it. Existing installations and running containers are handled without creating a duplicate clone.

Run the setup and open the local ARTEX interface:

```powershell
Set-Location '.\generic'
.\Check-ArtexSetup-v1.1.0.ps1 -OpenBrowser
```

Use a different repository location or installed Ollama model when required:

```powershell
.\Check-ArtexSetup-v1.1.0.ps1 `
    -RepositoryPath 'C:\Tools\ARTEX' `
    -OllamaModel 'your-installed-model'
```

Docker Desktop and Ollama must already be installed and operational. When either prerequisite is unavailable, the script reports why the environment is not ready and provides the applicable installation resource rather than attempting automated debugging.

### `Start-ArtexWebAssessment-v1.1.0.ps1`

**Repository path:** `generic/Start-ArtexWebAssessment-v1.1.0.ps1`  
**Current version:** 1.1.0  
Creates a generic first-run ARTEX web-assessment package for an operator-supplied HTTPS origin. The script validates the local ARTEX, Docker, Git, and Ollama environment; checks target DNS and HTTPS reachability; writes a timestamped campaign prompt and metadata file; copies the prompt to the clipboard; and displays Microsoft Edge extension setup steps. Campaign files are saved under `C:\Tools\ARTEX-Campaigns` by default.

Create a first-run campaign for an authorized non-production web application:

```powershell
Set-Location '.\generic'
.\Start-ArtexWebAssessment-v1.1.0.ps1 `
    -Domain 'https://app.example.test'
```

Use the baseline profile or a different campaign-data directory:

```powershell
.\Start-ArtexWebAssessment-v1.1.0.ps1 `
    -Domain 'https://app.example.test' `
    -Profile Baseline `
    -CampaignRoot 'C:\SecurityTesting\ARTEX-Campaigns'
```

Supply only the HTTPS origin, without credentials, query parameters, fragments, or an application path. Authentication, when required, is established through the normal browser workflow.

### `Test-Feeds3.ps1`

**Repository path:** `generic/Test-Feeds3.ps1`  
**Current version:** 2.0.1

Performs a lightweight, read-only reachability comparison using current OpenPhish URL indicators and IPSum IP indicators. The script is intended to help assess whether a machine's DNS, network, browser-independent filtering, firewall, or upstream security controls appear to prevent connections to sampled threat-intelligence indicators.

The tool reports **reachable** and **not reachable** rather than claiming that every failed connection was blocked. DNS resolution failure, NRPT, secure DNS, firewalls, routing, server shutdown, feed churn, hosting-provider takedown, or a closed TCP port can all produce a not-reachable result.

#### Intelligence sources

1. **OpenPhish Community Feed**  
   `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`

   Supplies phishing URLs. The test extracts each URL's hostname and advertised HTTP or HTTPS port, deduplicates hostname-and-port combinations, and performs a TCP reachability test.

2. **IPSum**  
   `https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt`

   Supplies suspicious or malicious IP addresses compiled from multiple public lists. The script tests each sampled IP on TCP ports 80 and 443 and records one result per IP.

URLhaus is no longer used. Its former unauthenticated CSV download endpoint returned HTTP 410 Gone, and URLhaus bulk exports now require a different authenticated workflow.

#### What the tool does

- Downloads both current feeds at runtime.
- Uses the first 25 feed entries per source when `-Quick` is specified.
- Deduplicates repeated OpenPhish hostname-and-port combinations.
- Counts each IPSum IP as one indicator even though ports 80 and 443 may both be tested.
- Supports a configurable TCP timeout through `-TimeoutMs`.
- Verifies that summary accounting is internally consistent before returning success.
- Returns exit code `0` after a consistent completed run and exit code `2` if the final accounting does not reconcile.

#### Usage

Run a quick test using up to 25 entries from each feed:

```powershell
Set-Location '.\generic'

.\Test-Feeds3.ps1 -Quick
```

Use a longer TCP timeout when the network is slow or heavily filtered:

```powershell
.\Test-Feeds3.ps1 `
    -Quick `
    -TimeoutMs 3000
```

Check the process exit code immediately after execution:

```powershell
$LASTEXITCODE
```

#### Interpreting results

A valid summary satisfies both equations:

```text
Unique entries tested + duplicates skipped = entries scheduled
Reachable results + not reachable results = unique entries tested
```

Important limitations:

- **Not reachable is not proof of filtering.** The destination may be offline, removed, unroutable, or not listening on the tested port.
- **Reachable is not proof of compromise or exploitability.** It means only that the TCP connection succeeded at test time.
- **IPSum is not a DNS-filtering test.** IPSum uses literal IP addresses, so DNS filtering and NRPT cannot affect those direct-IP tests.
- OpenPhish and IPSum are dynamic feeds. Different runs can produce different indicators and results.
- The script does not browse phishing pages, submit credentials, download payloads, or attempt exploitation.

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

Given a list of domains, provides DNS info. I use it in combination with the domains in a tenant to get info on them (is it on wix, aws, etc..)

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

If you want to automatically do so after every reboot & login event, run this PowerShell to create a Scheduled Task which will run that .ps1 for you under SYSTEM.
```powershell
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\analyst\DisableWindowsDefender.ps1"'
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
### `crt_enum.ps1`

Enumerates certificate-transparency and aggregated subdomain data from crt.sh and crt.name, then tests common TCP ports and performs basic HTTP(S) fingerprinting.

```powershell
cat t.csv
Asset Name
foo.com

.\crt_enum.ps1 -CsvPath .\t.csv
```

---
### `Set-DynamicNrptDomainBlock.ps1`

**Repository path:** `generic/Set-DynamicNrptDomainBlock.ps1`  
**Current version:** 2.5.0

Creates and maintains local Windows Name Resolution Policy Table (NRPT) sinkhole rules for validated malicious or high-risk DNS namespaces. The script downloads current intelligence, builds a normalized and deduplicated replacement catalog in memory, applies the local allow-list, and then transactionally replaces only the NRPT rules owned by the tool.

Every managed rule uses:

```text
Comment tag: RMMBlockTest
Sinkhole DNS server: 127.0.0.1
```

Rules created by Group Policy, Intune, VPN software, Windows, or another application are preserved.

#### Intelligence sources

1. **LOLRMM RMM domains**  
   `https://lolrmm.io/api/rmm_domains.csv`

   Provides domains associated with remote monitoring and management products. RMM products are dual-use, so approved organizational services should be added to the local allow-list before execution.

2. **Phishing.Database permanent domains**  
   `https://raw.githubusercontent.com/Phishing-Database/phishing/master/additions/permanent/domains.list`

   Provides community-maintained phishing-domain intelligence.

3. **OpenPhish Community Feed**  
   `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`

   Provides complete phishing URLs. Version 2.5.0 extracts and blocks only the exact DNS hostname from each URL. It does not derive or block the shared-hosting apex. For example, a malicious tenant under `pages.dev`, `github.io`, `vercel.app`, `blogspot.com`, or `weebly.com` is handled as an exact tenant hostname rather than blocking the entire platform.

4. **Helpdesk campaign domains, November 2026**  
   `https://raw.githubusercontent.com/anuragmalwranalysis/IOC/main/helpdesk%20Domain%20List%20-%20Nov%202026`

   Provides campaign-specific Helpdesk-themed phishing indicators.

5. **Local operator-maintained known-bad list**

   Accepts plain domains or complete URLs. URLs are reduced to their exact DNS hostname before validation.

```powershell
$KnownBadEntries = @(
    'https://cladesktop-apps.com/',
    'https://teams-cloud.live/'
)
```

#### Transactional refresh model

Version 2.5.0 performs a full current-feed replacement on each successful run:

1. Download every mandatory source with retries.
2. Parse, normalize, validate, and deduplicate all indicators in memory.
3. Preserve all contributing source names when the same hostname appears in multiple feeds.
4. Apply the allow-list to the completed catalog.
5. Refuse to modify NRPT if the final catalog is empty or unexpectedly small.
6. Read and preserve NRPT rules owned by other controls.
7. Remove only rules tagged `RMMBlockTest` after the complete replacement catalog is valid.
8. Install the current catalog.
9. If installation fails, remove the partial replacement and restore the previous tool-owned catalog.

This model removes stale tool-owned rules when domains disappear from all current feeds. A hostname remains in the catalog when at least one current source still supplies it.

#### Safety and precision controls

Before changing NRPT, the script:

- Downloads each source with retry logic and validates that usable content was returned.
- Extracts exact hostnames from URL feeds.
- Rejects literal IP addresses because NRPT controls DNS resolution and cannot block direct-IP connections.
- Rejects embedded wildcard, regular-expression, path, CIDR, port-qualified, and malformed DNS entries that NRPT cannot represent safely.
- Deduplicates namespaces across all feeds while retaining source attribution.
- Applies the local allow-list as the final catalog override.
- Requires at least 100 validated namespaces before beginning replacement.
- Preserves non-tool NRPT rules.
- Uses rollback protection if the new catalog cannot be installed completely.
- Returns a nonzero exit code when the refresh cannot be completed safely.

The local allow-list permits each listed domain and its subdomains. The current defaults protect approved GitHub, Python package, and Google Workspace services:

```powershell
$AllowedDomains = @(
    'github.com',
    'raw.githubusercontent.com',
    'pypi.org',
    'pythonhosted.org',
    'githubassets.com',
    'objects.githubusercontent.com',
    'release-assets.githubusercontent.com',
    'media.githubusercontent.com',
    'gist.githubusercontent.com',
    'docs.google.com',
    'drive.google.com',
    'accounts.google.com'
)
```

Review and adapt this allow-list before deployment in another environment.

#### Run the script

Run from an elevated PowerShell session:

```powershell
Set-Location '.\generic'

.\Set-DynamicNrptDomainBlock.ps1
```

Suppress per-domain progress while retaining stage and summary output:

```powershell
.\Set-DynamicNrptDomainBlock.ps1 -NoProgress
```

Review rules created by the script:

```powershell
Get-DnsClientNrptRule |
    Where-Object Comment -eq 'RMMBlockTest' |
    Select-Object DisplayName, Namespace, NameServers, Comment
```

Remove all rules owned by the script:

```powershell
.\Set-DynamicNrptDomainBlock.ps1 -Remove
```

#### Successful validation example

A validated version 2.5.0 run produced:

```text
Unique validated namespaces after allow-list: 5275
Previous tool-owned rules removed: 5275
Current rules added: 5275
Skipped because another owner already manages the namespace: 0
Failed: 0
```

Feed counts are point-in-time values and will change as upstream intelligence changes.

#### Scheduling

The script is suitable for scheduled execution after interactive validation. A scheduled task should run the script elevated, use `-NoProgress`, start only when networking is available, and preserve the previous catalog when a mandatory feed cannot be validated.

Example command line:

```powershell
pwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "C:\Tools\PowerShell-Scripts\generic\Set-DynamicNrptDomainBlock.ps1" -NoProgress
```

#### Limitations

- NRPT blocks DNS namespaces, not complete URLs or URL paths.
- NRPT cannot block direct connections to literal IP addresses.
- Applications that bypass the Windows DNS client or use independent encrypted DNS may not honor NRPT rules.
- Feed inclusion is threat intelligence, not permanent proof that every listed hostname remains malicious.
- Exact-host blocking on shared infrastructure reduces collateral impact but does not validate every upstream classification independently.
- Rebuilding thousands of NRPT rules creates local rule churn and is not a replacement for enterprise protective DNS or a Secure Web Gateway.
- This control complements, but does not replace, SmartScreen, EDR, secure web gateways, DNS filtering, firewall controls, email security, patching, or user awareness.

---
### `Invoke-CveRiskAssessment.ps1`
  
Performs a read-only, evidence-driven CVE assessment from a plain-text list of CVE identifiers. The script automatically downloads or reuses the current CISA Known Exploited Vulnerabilities catalog and FIRST EPSS daily feed, retrieves NVD CVSS and description evidence, and exports structured CSV, JSON, Excel, and feed-manifest artifacts.

The script deliberately separates:
- **CVSS** technical severity
- **EPSS** predicted exploitation probability and percentile
- **CISA KEV** confirmed known exploitation
- **Asset applicability** based on operator-supplied evidence
- **Contextual priority** based on applicability, exposure, business criticality, and compensating controls

Missing asset context remains **Unknown**. The tool does not infer that a CVE affects an asset merely because the CVE appears in KEV, has a high EPSS score, or has a high CVSS score.

#### Input

Create a text file containing one CVE identifier per line. Blank lines and lines beginning with `#` are ignored. Duplicate identifiers are removed automatically.

```text
CVE-2021-44228
CVE-2023-34362
CVE-2024-3400
```

Run from the generic directory:

```powershell
Set-Location '.\generic'

.\Invoke-CveRiskAssessment.ps1 `
    -CveListPath '.\cves.txt'
```

#### Optional asset context

Asset context is optional. When `-ContextCsvPath` is omitted, the script performs threat-intelligence enrichment and creates `Asset-Context-Template.csv` in the output directory. The generated template can then be populated with evidence for:

- Asset exposure
- Affected-version confirmation
- Reachability
- Exploit prerequisites
- Compensating controls
- Component presence in the deployed artifact
- Business criticality
- Evidence and evidence source

Run a context-aware assessment:

```powershell
.\Invoke-CveRiskAssessment.ps1 `
    -CveListPath '.\cves.txt' `
    -ContextCsvPath '.\Asset-Context.csv'
```

#### Data sources and caching

The script automatically:
- Downloads the CISA KEV JSON catalog.
- Downloads and decompresses the FIRST EPSS daily CSV.
- Retrieves NVD CVE records, descriptions, status, publication dates, and available CVSS metrics.
- Caches KEV and EPSS feeds under the current user's local application-data directory for 24 hours by default.
- Records source URLs, timestamps, record counts, file hashes, input-file hash, and NVD usage in a feed manifest.

Use `-ForceFeedRefresh` to download fresh KEV and EPSS files regardless of cache age. Set the `NVD_API_KEY` environment variable when an NVD API key is available; do not place API keys in scripts or repositories.

#### Outputs

Each run creates a timestamped output directory containing:
- A detailed CSV assessment
- Matching JSON evidence
- A formatted Excel workbook
- A feed-manifest JSON file
- An automatically generated asset-context template when no context CSV is supplied
- Invalid-input and collection-error CSV files when applicable

#### Interpretation

Applicability is reported as:
- **Confirmed**
- **LikelyOrProbable**
- **Inconclusive**
- **NotConfirmed**

Contextual priority is reported as:
- **P1_CRITICAL**
- **P2_HIGH**
- **P3_MEDIUM**
- **P4_LOW**
- **VALIDATE_URGENTLY**
- **VALIDATE**
- **DEPRIORITIZE_PENDING_NEW_EVIDENCE**

Priority is not derived from CVSS, EPSS, or KEV alone. A confirmed, Internet-accessible vulnerability requires applicable component, version, reachability, prerequisite, and context evidence before the script assigns a remediation priority. A negative or not-detected result is point-in-time evidence and does not prove permanent absence.

The script requires PowerShell 7.2 or later and the ImportExcel module. ImportExcel is installed for the current user when missing unless `-DoNotInstallMissingModules` is specified.

This product uses data from the NVD API but is not endorsed or certified by the NVD.

### `Test-GitHubRepositorySecurity.ps1`

`Test-GitHubRepositorySecurity.ps1` performs a read-only assessment of security controls configured for one or more GitHub repositories. It uses the authenticated GitHub CLI session to collect repository and default-branch evidence, then reports whether key GitHub security capabilities are enabled, unavailable, or require additional validation.

#### What the tool checks

- Repository visibility and default-branch context.
- Branch protection and repository rulesets governing the default branch.
- GitHub code-scanning configuration and available analysis evidence.
- Dependabot security-alert availability and configuration evidence.
- Secret-scanning and push-protection availability where exposed by the GitHub API and current token permissions.
- Collection limitations caused by repository plan, feature availability, API responses, or insufficient scoped access.

The tool treats missing API evidence conservatively. A control is not reported as absent merely because the authenticated account cannot read the corresponding endpoint. Review results together with the permission and collection-status evidence shown in the report.

#### Prerequisites

- PowerShell 7 is recommended.
- GitHub CLI (`gh`) must be installed.
- `gh auth status` must show an authenticated account with access to the repositories being assessed.
- The authenticated token must have sufficient repository and security-event visibility for the controls being queried.

#### Usage

Run from the generic directory and provide one or more repositories in `owner/name` format:

```powershell
Set-Location '.\generic'
.\Test-GitHubRepositorySecurity.ps1 `
    -Repository 'owner/first-repository', 'owner/second-repository'
```

#### Interpretation and limitations

- A successful API response is stronger evidence than a repository setting inferred from public metadata.
- `Not configured`, `not detected`, `unavailable`, and `access denied` are different outcomes and should not be treated as equivalent.
- The assessment is point-in-time and read-only. It does not enable GitHub Advanced Security, create rulesets, change branch protection, dismiss alerts, or modify repository settings.
- Repository access alone may not provide access to code-scanning, Dependabot, secret-scanning, or organization-level policy evidence.

### `Invoke-PythonRepositorySecurityScan.ps1`

`Invoke-PythonRepositorySecurityScan.ps1` orchestrates a repeatable local security scan of an already-cloned Python repository and consolidates the available scanner results into a practical review workflow. It reduces setup and reporting friction while preserving the evidence and limitations of each underlying scanner.

#### What the tool does

- Accepts the local path of a cloned Python repository.
- Validates the local Python scanning environment before starting the assessment.
- Runs the configured dependency and static-analysis scanners against the repository.
- Continues through individual scanner failures where practical so that one unavailable tool does not discard all other results.
- Collects scanner output and produces a consolidated report for technical review and evidence sharing.
- Keeps scanner findings separate from the final pass/fail rationale so that unverified findings are not automatically treated as confirmed vulnerabilities.

The workflow can use Bandit, pip-audit, Semgrep, and Trivy when those tools are installed and available in the configured environment. Each scanner provides different coverage, so dependency findings, source-code patterns, secrets, and repository or filesystem issues must be interpreted according to the tool that produced them.

#### Prerequisites

- The target repository must already be cloned locally.
- PowerShell 7 is recommended.
- Python and the repository-scanning virtual environment must be available as described in `Invoke-PythonRepositorySecurityScan-README-v1.1.1.txt`.
- Scanner availability and authentication requirements vary by tool. Review warnings when a scanner is skipped, unavailable, or returns incomplete results.

#### Usage

Run from the generic directory and point the script to the cloned repository:

```powershell
Set-Location '.\generic'
.\Invoke-PythonRepositorySecurityScan.ps1 `
    -RepositoryPath 'C:\Path\To\ClonedRepository'
```

Review the script's comment-based help for its complete current parameter set:

```powershell
Get-Help .\Invoke-PythonRepositorySecurityScan.ps1 -Full
```

#### Interpretation and limitations

- Scanner output is a lead for review, not automatic proof of exploitability.
- Dependency findings require confirmation that the affected package and version are deployed or reachable in the application path.
- Static-analysis findings require source review and, where appropriate, controlled reproduction of the reported behavior.
- A clean result is limited to the tools, rules, files, dependencies, exclusions, and repository revision assessed during that run.
- The orchestrator does not replace manual code review, deployment validation, runtime testing, or verification of compensating controls.

### `WP-CVE-Validator.ps1`

**Repository path:** `generic/WP-CVE-Validator.ps1`  
**Current version:** 3.7.2

WP-CVE-Validator.ps1 is an evidence-first, read-only PowerShell tool for assessing public WordPress and PHP deployments against a curated vulnerability catalog. Version 3.7.2 combines safe behavioral and prerequisite validation with NVD CVSS severity, the CISA Known Exploited Vulnerabilities catalog, and FIRST EPSS exploitation-probability data.

The tool keeps asset applicability separate from threat intelligence. CVSS, KEV, and EPSS enrich the exported evidence, but the console displays the detailed threat banner only when vulnerable behavior is confirmed. Affected-version evidence, exposed prerequisites, and observed behavior are reported without being mislabeled as reproduced exploitation.

##### What the tool does

- Detects publicly observable WordPress installations and core versions.
- Inventories exposed plugins and themes and records the evidence source for each component.
- Correlates reliable component versions with affected CVE ranges.
- Performs safe, read-only behavioral, differential, and prerequisite checks.
- Downloads or reuses the current CISA KEV catalog and FIRST EPSS feed.
- Retrieves NVD CVSS scores, severity, vectors, and scoring sources for cataloged CVEs.
- Caches KEV, EPSS, and NVD evidence under `%LOCALAPPDATA%\WP-CVE-Validator\ThreatCache` for 24 hours by default.
- Exports CVSS, KEV, EPSS, affected-version evidence, behavior evidence, and contextual dispositions to CSV and JSON.
- Creates a threat-intelligence manifest containing source URLs, feed hashes, record counts, KEV metadata, and NVD attribution.
- Distinguishes confirmed vulnerable behavior, exposed prerequisites, affected component versions, observed exposures, inconclusive results, and checks that are not applicable.
- Identifies Cloudflare response-path indicators without assuming that Cloudflare completely protects or conceals the origin.
- Performs evidence-based managed-hosting attribution using DNS, reverse DNS, and HTTP response headers.
- Preserves separate IPv4 and IPv6 values in exported DNS evidence.
- Deduplicates aggregate results by canonical application.
- Runs catalog boundary tests and validates CSV/JSON export integrity before completing.

##### Console presentation

The console uses color to separate operational failures from security conclusions:

- Red `DOWN/UNREACHABLE` or failed HTTP status lines indicate request failures.
- Yellow warnings indicate inconclusive status, affected-version evidence, or validation requirements.
- Magenta `[EXPOSURE]` headings identify reproduced security-relevant behavior that does not prove the associated historical CVE applies. For example, public REST user enumeration on a site whose WordPress Core version is unknown is reported as an exposure without falsely attributing CVE-2017-5487.
- A blinking red `[VULNERABLE]` threat line is reserved for **Confirmed Vulnerable Behavior**. In PowerShell 7, the tool requests ANSI blinking; terminals that do not support blinking receive a magenta fallback.

The detailed threat line includes current CVSS, KEV, EPSS probability, EPSS percentile, and threat-priority context. It is suppressed for fixed versions, unaffected versions, unknown versions, denied requests, authentication-required results, unreproduced behavior, and other inconclusive outcomes.

##### Safety boundaries

The validator does **not** perform authentication, account creation, SQL payload delivery, file uploads, file promotion, code execution, privilege escalation, core updates, race-condition exploitation, installer submission, database configuration, directory enumeration, or direct-to-origin testing.

The CVE-2026-60137 differential check uses only safe, non-SQL malformed input. The October 28 WordPress Core assessment and CVE-2026-119977 reuse the same read-only `GET` and `HEAD` requests to `/wp-content/upgrade/`, `/wp-content/upgrade/index.php`, and a randomized nonexistent child path. The tool does not start an update, upload a package, race the updater, submit installer settings, or attempt to execute staged PHP.

For CVE-2026-114432, the validator performs passive Contact Form 7 discovery, version correlation, and public HTML review for a file-upload field. It does not submit the form, upload a validation file, probe temporary-file persistence, enumerate upload directories, retrieve active content, or attempt PHP/PHAR execution.

##### Vulnerability coverage

Version 3.7.2 contains **16 CVE checks** plus the separate WP-CORE-2026-10-28 security-baseline assessment.

###### WordPress October 28, 2026 security baseline

- **WP-CORE-2026-10-28:** Compares an observed WordPress Core version with the corresponding October 28, 2026 security backport for branches 4.7 through 7.1, including WordPress 7.1.4, 7.0.8, 6.9.11, and 6.8.12.
- Sends differential read-only requests to `/wp-content/upgrade/`, `/wp-content/upgrade/index.php`, and a randomized nonexistent child path.
- Records status codes, effective URLs, response sizes, body signatures, directory-listing markers, installer markers, and soft-404 similarity.
- Reports an exposed prerequisite only when a credible upgrade-directory or installer signal differs from the randomized control and remains under the expected upgrade path.
- Does not label the upgrade-window RCE as reproduced. A negative point-in-time check does not prove that the transient artifact would be unreachable during a real update.

###### WordPress Core CVEs

- **CVE-2017-5487:** Safely checks the WordPress REST users endpoint. Public user enumeration on WordPress 4.7.0 can be classified as confirmed vulnerable behavior. The same behavior on a newer version, or when Core version is unknown, is reported as an observed exposure without falsely attributing the historical CVE.
- **CVE-2026-119977:** WordPress Core upgrade-window staged-installer RCE eligibility. Reuses the WP-CORE-2026-10-28 branch-version matrix and upgrade-path evidence instead of sending duplicate probes. The check distinguishes fixed releases, affected releases without an observed transient artifact, affected releases with a public staging prerequisite, and unknown-version results.
- **CVE-2026-60137:** WordPress `WP_Query` SQL-injection eligibility involving `author__not_in`, assessed with a safe differential prerequisite probe rather than SQL payloads.
- **CVE-2026-63030:** WordPress REST batch-route confusion.
- **CVE-2026-65640:** Imagick/Ghostscript PostScript upload-RCE eligibility. The tool evaluates version evidence and public prerequisites but does not upload a file.
- **CVE-2026-87902:** WordPress page-template path traversal/LFI with conditional RCE eligibility. The tool performs passive branch-version comparison only.

###### WordPress plugin CVEs

- **CVE-2026-1492:** WPEverest User Registration privilege-escalation exposure through version 5.1.2.
- **CVE-2026-19949:** All-in-One WP Migration affected-version correlation. The tool does not perform a migration, restore operation, or second-order SQL-injection workflow.
- **CVE-2026-23550:** Modular DS / Modular Connector unauthenticated privilege-escalation exposure through version 2.5.1; version 2.5.2 is treated as the first fixed release.
- **CVE-2026-78006:** The Events Calendar affected-version correlation.
- **CVE-2026-83627:** Hummingbird Performance affected-version correlation.
- **CVE-2026-85097:** Bricksforge unauthenticated arbitrary-file-upload/RCE exposure through version 3.1.8.9. The tool does not retrieve a nonce, upload a file, submit a form, promote a temporary file, or attempt execution.
- **CVE-2026-8809:** Advanced Custom Fields: Extended privilege escalation through version 0.9.2.5. Exploitation requires a public frontend Create User form with a mapped role field; the tool does not submit forms, manipulate roles, or create accounts.
- **CVE-2026-114432:** Contact Form 7 unauthenticated arbitrary-file-upload exposure in versions 6.2 through 6.2.3; version 6.2.4 is treated as the first fixed release. The tool can passively observe a public Contact Form 7 file field, but it does not submit a form or upload a file. Arbitrary file persistence is the primary issue; remote code execution additionally depends on server behavior such as discoverable uploads and executable handler mappings.

###### PHP Core CVEs

- **CVE-2026-109618:** PHP unauthenticated remote-code-execution exposure involving out-of-memory corruption.
- **CVE-2026-109619:** PHP unauthenticated remote-code-execution exposure involving stale request-owned global state.

PHP findings rely on publicly disclosed version evidence. Hidden versions remain inconclusive, and externally observed versions may require hosting-side confirmation because managed platforms and Linux distributions can apply backported fixes.

##### Evidence classifications

- **Confirmed Vulnerable Behavior:** The central safe behavior was reproduced with sufficient applicability evidence. The console adds the blinking red threat banner.
- **Confirmed Exposed Prerequisite:** A material prerequisite was observed, but the complete exploit path was not reproduced.
- **Affected Component Version:** Reliable Core, plugin, or PHP version evidence falls inside an affected range, while behavior or configuration prerequisites remain unverified. Version 3.7.2 uses a common classifier so affected Core, plugin, PHP, legacy PHP, generic component, and potentially affected version wording contributes consistently to target and aggregate dispositions.
- **Observed Exposure:** Public behavior or metadata warrants review but does not prove the associated CVE. The console uses a prominent magenta/yellow exposure warning.
- **Inconclusive:** Version, component presence, configuration, or response behavior could not be established reliably.
- **Not detected / not applicable:** The component or required condition was not observed. This does not prove permanent absence.

Partial WordPress versions such as 7.1 should be treated as patch-level inconclusive unless another public source provides the complete version. WP-CLI, the WordPress administration interface, managed-hosting inventory, or filesystem evidence remain authoritative for final patch validation.

##### Usage

Create a text file containing one hostname or URL per line:

```text
example.com
www.example.org
https://wordpress.example.net/blog
```

Run the validator from the generic directory:

```powershell
Set-Location '.\generic'
.\WP-CVE-Validator.ps1 `
    -DomainListPath '.\wordpress-domains.txt'
```

Force fresh KEV and EPSS feeds:

```powershell
.\WP-CVE-Validator.ps1 `
    -DomainListPath '.\wordpress-domains.txt' `
    -ForceThreatFeedRefresh
```

Set `NVD_API_KEY` when an NVD API key is available. Do not place API keys in scripts or repositories.

##### Output

The validator produces:

- A detailed timestamped CSV evidence report.
- A matching JSON evidence report.
- `WP-CVE-Validator-Coverage-v3.7.2.csv`, describing each check, validation mode, coverage, and limitations.
- `WP-CVE-Validator-Threat-Manifest-YYYYMMDD-HHMMSS.json`, recording threat-feed sources, hashes, record counts, and NVD usage.
- Console summaries for raw targets and deduplicated canonical applications.
- CVSS, CISA KEV, FIRST EPSS, Core, plugin, theme, PHP, Cloudflare, hosting, DNS, and request evidence.
- Automatic CSV/JSON integrity and URL-ownership validation.

##### Interpretation and limitations

- Scanner fingerprints, public references, and version strings are evidence leads, not automatic proof of exploitability.
- A successful Cloudflare-path response proves the tested public response traversed Cloudflare; it does not prove WAF enforcement, origin concealment, or prevention of direct-to-origin access.
- Managed-hosting attribution does not replace authoritative patch verification.
- The `/wp-content/upgrade/` condition is transient. A clean point-in-time response cannot prove that the vulnerable window never exists.
- Plugin presence without a reliable version remains inconclusive.
- Contact Form 7 RCE is conditional on server configuration; an affected plugin version alone is not proof of executable upload or RCE.
- The tool does not replace authenticated configuration review, WP-CLI, source-code review, server inventory, log analysis, provider confirmation, or controlled nonproduction exploitation.

#### SSH-CVE-Validator.ps1

`SSH-CVE-Validator.ps1` is an evidence-first, read-only PowerShell tool for validating public SSH and OpenSSH exposure against a curated server-side CVE catalog. Version 1.2.4 combines direct SSH banner collection, Nmap protocol negotiation, IP-and-port endpoint deduplication, hosting attribution, and current NVD CVSS, CISA Known Exploited Vulnerabilities, and FIRST EPSS threat intelligence.

The validator separates asset applicability from general threat severity. A version banner is treated as an evidence lead rather than proof of vulnerability. Confirmed protocol conditions, affected-version evidence, platform exclusions, missing server-side prerequisites, provider ownership, and point-in-time reachability are reported separately.

##### What the tool does

- Accepts an IONIX action-item CSV or a text file containing one hostname, IP address, or `host:port` target per line.
- Reads nonstandard SSH ports from IONIX `Technical Details`, including TCP/2222.
- Resolves each input to a public IP and deduplicates active testing by unique `IP:port` endpoint.
- Reuses SSH, Nmap, authentication, algorithm, and CVE evidence for DNS aliases that resolve to an endpoint already assessed.
- Retains hostname-level evidence and produces a second endpoint-level report containing primary names and aliases.
- Collects the SSH protocol identification banner without authenticating.
- Uses Nmap `ssh2-enum-algos` and `ssh-auth-methods` to collect advertised algorithms and authentication methods.
- Detects Internet-reachable SSH password authentication and highlights it as an exposure requiring review.
- Identifies OpenSSH versions and platform indicators such as Ubuntu, Debian, Alpine Linux, FreeBSD, or Windows when disclosed in the banner.
- Attributes hosting provider and network owner using validated IP mappings, DNS, authoritative nameservers, and reverse DNS.
- Downloads or reuses the current CISA KEV catalog and FIRST EPSS daily feed.
- Retrieves NVD CVSS scores, severity, vectors, and scoring sources for cataloged CVEs.
- Caches KEV, EPSS, and NVD evidence under `%LOCALAPPDATA%\SSH-CVE-Validator\ThreatCache` for 24 hours by default.
- Exports hostname-level and endpoint-level CSV and JSON evidence, a coverage ledger, and a threat-intelligence manifest.
- Displays CVSS, KEV, EPSS probability, EPSS percentile, and evidence-based priority only when an endpoint is confirmed affected.

##### Console presentation

- **Green:** Reachable service, known hosting attribution, fixed or unaffected version, platform not affected, Terrapin strict-key-exchange mitigation present, or prerequisite not observed.
- **Yellow:** Password authentication, affected-version evidence, missing prerequisites, unknown vendor patch status, provider follow-up, or inconclusive results.
- **Red:** TCP failure, timeout, or unreachable SSH endpoint.
- **Magenta `[EXPOSURE]`:** Reproduced security-relevant behavior such as Internet-reachable password authentication or confirmed Terrapin protocol prerequisites.

A confirmed endpoint/CVE pair receives a current threat summary:

```text
[THREAT] CVE-2023-48795 | CVSS 5.9 MEDIUM |
CISA KEV: NO | EPSS: <current probability>% |
Percentile: <current percentile>%
[!] Priority: CONFIRMED AFFECTED + HIGH EPSS - REMEDIATE
```

High CVSS, KEV status, or EPSS probability alone does not cause the tool to declare an endpoint affected.

##### Vulnerability coverage

Version 1.2.4 checks five SSH or OpenSSH CVEs:

- **CVE-2023-48795, Terrapin:** Evaluates advertised SSH algorithms for strict key exchange, ChaCha20-Poly1305, CBC ciphers, and Encrypt-then-MAC combinations without packet manipulation or exploitation.
- **CVE-2024-6387, regreSSHion:** Identifies OpenSSH versions in the upstream regression range while preserving platform, `LoginGraceTime`, and vendor-backport limitations.
- **CVE-2025-26466:** Identifies affected upstream OpenSSH versions while preserving vendor patch and `PerSourcePenalties` limitations.
- **CVE-2026-123158:** Requires evidence of Linux with musl libc, PAM disabled, password authentication enabled, relevant local-account state, and unpatched package status. Disclosed Ubuntu and other non-musl platforms are not applicable.
- **CVE-2026-60000:** Correlates affected versions with observed GSSAPI authentication support while retaining vendor-package and effective-configuration limitations.

##### Endpoint deduplication

The cache key is the resolved public IP plus TCP port. `192.0.2.10:22` and `192.0.2.10:2222` are distinct endpoints, while multiple DNS names resolving to `192.0.2.10:22` are actively assessed once. Aliases remain in hostname-level output and are consolidated in the endpoint-level `Aliases` field.

##### Safety boundaries

The validator does **not** authenticate, submit credentials, brute-force accounts, attempt the CVE-2026-123158 long-password bypass, manipulate SSH packets, execute commands, upload files, or change SSH, PAM, firewall, account, key, or package configuration.

Nmap uses a deliberately nonexistent probe account to request server-advertised authentication methods. When a server returns no methods for that account, the result remains `Unknown` rather than being treated as password authentication disabled.

##### Input and usage

Run against an IONIX action-item CSV:

```powershell
Set-Location '.\generic'

.\SSH-CVE-Validator.ps1 `
    -InputPath '.\IONIX-Open-Action-Items.csv'
```

Minimal CSV:

```csv
Asset Name,Technical Details
ssh.example.com,"{'port': 22}"
192.0.2.10,"{'port': 2222}"
```

Plain-text input is also supported:

```text
ssh.example.com
192.0.2.10:2222
[2001:db8::10]:22
```

Use `-SkipNmap` only when banner and reachability evidence are sufficient. Skipping Nmap prevents fresh authentication-method and SSH-algorithm validation, including deterministic Terrapin assessment.

##### Threat intelligence and caching

The validator downloads or reuses the CISA KEV JSON catalog and FIRST EPSS daily CSV, retrieves NVD CVE and CVSS evidence, caches threat intelligence for 24 hours, and records feed paths, source URLs, hashes, record counts, timestamps, and NVD usage. Use `-ForceThreatFeedRefresh` for fresh KEV and EPSS data. Set `NVD_API_KEY` when available; do not place API keys in scripts or repositories.

##### Output

Each run produces:

- `SSH-CVE-Validator-Results-YYYYMMDD-HHMMSS.csv` and matching hostname-level JSON.
- `SSH-CVE-Validator-Endpoints-YYYYMMDD-HHMMSS.csv` and matching endpoint-level JSON.
- `SSH-CVE-Validator-Coverage-v1.2.4.csv`.
- `SSH-CVE-Validator-Threat-Manifest-YYYYMMDD-HHMMSS.json`.

The hostname output preserves source names and IONIX identifiers. The endpoint output reports one row per unique IP:port endpoint with aliases.

##### Interpretation and limitations

- A banner confirms the advertised version string, not the effective vendor patch level.
- Linux distributions and hosting providers may backport fixes without changing the banner.
- Terrapin protocol applicability can be established from negotiated algorithms without reproducing packet manipulation or impact.
- CVE-2026-123158 requires server-side libc, PAM, package, and account evidence that cannot be established from a public banner alone.
- Password authentication is a security-relevant exposure, not proof of compromise or of a specific CVE.
- Unreachable is point-in-time evidence and does not prove permanent absence.
- Hosting attribution helps identify likely remediation ownership, while account-level users, keys, shell access, and provider escalation may remain with the customer.
- The tool does not replace authenticated configuration review, package inventory, server logs, provider confirmation, or controlled nonproduction exploitation.
