# Azure AD New MFA Method Registered For User

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the registration of a new Multi-Factor Authentication (MFA) method for an Azure AD account. It leverages Azure AD AuditLogs to identify when a user registers new security information. This activity is significant because adversaries who gain unauthorized access to an account may add their own MFA method to maintain persistence. If confirmed malicious, this could allow attackers to bypass existing security controls, maintain long-term access, and potentially escalate their privileges within the environment.

## MITRE ATT&CK

- T1556.006

## Analytic Stories

- Compromised User Account
- Azure Active Directory Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Azure Active Directory User registered security info

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.006/azure_ad_new_mfa_method_registered_for_user/azuread.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_new_mfa_method_registered_for_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
