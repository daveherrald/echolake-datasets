# Azure AD Multiple Denied MFA Requests For User

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting an unusually high number of denied Multi-Factor Authentication (MFA) requests for a single user within a 10-minute window, specifically when more than nine MFA prompts are declined. It leverages Azure Active Directory (Azure AD) sign-in logs, focusing on "Sign-in activity" events with error code 500121 and additional details indicating "MFA denied; user declined the authentication." This behavior is significant as it may indicate a targeted attack or account compromise attempt, with the user actively declining unauthorized access. If confirmed malicious, it could lead to data exfiltration, lateral movement, or further malicious activities.

## MITRE ATT&CK

- T1621

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory Sign-in activity

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/azure_ad_multiple_denied_mfa_requests/azure_ad_multiple_denied_mfa_requests.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_multiple_denied_mfa_requests_for_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
