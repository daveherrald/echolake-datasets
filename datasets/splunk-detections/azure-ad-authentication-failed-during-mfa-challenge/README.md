# Azure AD Authentication Failed During MFA Challenge

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk, 0xC0FFEEEE

## Description

This dataset contains sample data for identifying failed authentication attempts against an Azure AD tenant during the Multi-Factor Authentication (MFA) challenge, specifically flagged by error code 500121. It leverages Azure AD SignInLogs to detect these events. This activity is significant as it may indicate an adversary attempting to authenticate using compromised credentials on an account with MFA enabled. If confirmed malicious, this could suggest an ongoing effort to bypass MFA protections, potentially leading to unauthorized access and further compromise of the affected account.

## MITRE ATT&CK

- T1078.004
- T1586.003
- T1621

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/azuread/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_authentication_failed_during_mfa_challenge.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
