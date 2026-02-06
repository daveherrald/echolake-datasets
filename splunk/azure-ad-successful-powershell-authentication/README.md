# Azure AD Successful PowerShell Authentication

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic identifies a successful authentication event against an Azure AD tenant using PowerShell cmdlets. This detection leverages Azure AD SignInLogs to identify successful logins where the appDisplayName is "Microsoft Azure PowerShell." This activity is significant because it is uncommon for regular, non-administrative users to authenticate using PowerShell, and it may indicate enumeration and discovery techniques by an attacker. If confirmed malicious, this activity could allow attackers to perform extensive reconnaissance, potentially leading to privilege escalation or further exploitation within the Azure environment.

## MITRE ATT&CK

- T1078.004
- T1586.003

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/azuread_pws/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_successful_powershell_authentication.yml)*
