# Azure AD OAuth Application Consent Granted By User

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting when a user in an Azure AD environment grants consent to an OAuth application. It leverages Azure AD audit logs to identify events where users approve application consents. This activity is significant as it can expose organizational data to third-party applications, a common tactic used by malicious actors to gain unauthorized access. If confirmed malicious, this could lead to unauthorized access to sensitive information and resources. Immediate investigation is required to validate the application's legitimacy, review permissions, and mitigate potential risks.

## MITRE ATT&CK

- T1528

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory Consent to application

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1528/azure_ad_user_consent_granted/azure_ad_user_consent_granted.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_oauth_application_consent_granted_by_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
