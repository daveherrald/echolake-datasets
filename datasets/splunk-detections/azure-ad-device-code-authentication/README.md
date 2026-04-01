# Azure AD Device Code Authentication

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran,  Splunk

## Description

This dataset contains sample data for identifying Azure Device Code Phishing attacks, which can lead to Azure Account Take-Over (ATO). It leverages Azure AD SignInLogs to detect suspicious authentication requests using the device code authentication protocol. This activity is significant as it indicates potential bypassing of Multi-Factor Authentication (MFA) and Conditional Access Policies (CAPs) through phishing emails. If confirmed malicious, attackers could gain unauthorized access to Azure AD, Exchange mailboxes, and Outlook Web Application (OWA), leading to potential data breaches and unauthorized data access.

## MITRE ATT&CK

- T1528
- T1566.002

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1528/device_code_authentication/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_device_code_authentication.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
