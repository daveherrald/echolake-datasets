# Azure AD Successful Single-Factor Authentication

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic identifies a successful single-factor authentication event against Azure Active Directory. It leverages Azure SignInLogs data, specifically focusing on events where single-factor authentication succeeded. This activity is significant as it may indicate a misconfiguration, policy violation, or potential account takeover attempt. If confirmed malicious, an attacker could gain unauthorized access to the account, potentially leading to data breaches, privilege escalation, or further exploitation within the environment.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/azuread/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_successful_single_factor_authentication.yml)*
