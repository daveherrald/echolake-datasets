# O365 Mail Permissioned Application Consent Granted by User

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying instances where a user grants consent to an application requesting mail-related permissions within the Office 365 environment. It leverages O365 audit logs, specifically focusing on events related to application permissions and user consent actions. This activity is significant as it can indicate potential security risks, such as data exfiltration or spear phishing, if malicious applications gain access. If confirmed malicious, this could lead to unauthorized data access, email forwarding, or sending malicious emails from the compromised account. Validating the legitimacy of the application and consent context is crucial to prevent data breaches.

## MITRE ATT&CK

- T1528

## Analytic Stories

- Office 365 Account Takeover

## Data Sources

- O365 Consent to application.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1528/o365_user_consent_mail_permissions/o365_user_consent_mail_permissions.log


---

*Source: [Splunk Security Content](detections/cloud/o365_mail_permissioned_application_consent_granted_by_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
