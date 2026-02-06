# Azure AD Multiple Failed MFA Requests For User

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic identifies multiple failed multi-factor authentication (MFA) requests for a single user within an Azure AD tenant. It leverages Azure AD Sign-in Logs, specifically error code 500121, to detect more than 10 failed MFA attempts within 10 minutes. This behavior is significant as it may indicate an adversary attempting to bypass MFA by bombarding the user with repeated authentication prompts. If confirmed malicious, this activity could lead to unauthorized access, allowing attackers to compromise user accounts and potentially escalate their privileges within the environment.

## MITRE ATT&CK

- T1078.004
- T1586.003
- T1621

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory Sign-in activity

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/multiple_failed_mfa_requests/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_multiple_failed_mfa_requests_for_user.yml)*
