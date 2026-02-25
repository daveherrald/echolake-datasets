# Azure AD Multi-Factor Authentication Disabled

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting attempts to disable multi-factor authentication (MFA) for an Azure AD user. It leverages Azure Active Directory AuditLogs to identify the "Disable Strong Authentication" operation. This activity is significant because disabling MFA can allow adversaries to maintain persistence using compromised accounts without raising suspicion. If confirmed malicious, this action could enable attackers to bypass an essential security control, potentially leading to unauthorized access and prolonged undetected presence in the environment.

## MITRE ATT&CK

- T1556.006
- T1586.003

## Analytic Stories

- Azure Active Directory Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Azure Active Directory Disable Strong Authentication

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/azuread/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_multi_factor_authentication_disabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
