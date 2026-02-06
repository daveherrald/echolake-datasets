# O365 File Permissioned Application Consent Granted by User

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies instances where a user in the Office 365 environment grants consent to an application requesting file permissions for OneDrive or SharePoint. It leverages O365 audit logs, focusing on OAuth application consent events. This activity is significant because granting such permissions can allow applications to access, modify, or delete files, posing a risk if the application is malicious or overly permissive. If confirmed malicious, this could lead to data breaches, data loss, or unauthorized data manipulation, necessitating immediate investigation to validate the application's legitimacy and assess potential risks.

## MITRE ATT&CK

- T1528

## Analytic Stories

- Office 365 Account Takeover

## Data Sources

- O365 Consent to application.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1528/o365_user_consent_file_permissions/o365_user_consent_file_permissions.log


---

*Source: [Splunk Security Content](detections/cloud/o365_file_permissioned_application_consent_granted_by_user.yml)*
