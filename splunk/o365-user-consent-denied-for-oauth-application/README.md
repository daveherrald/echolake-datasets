# O365 User Consent Denied for OAuth Application

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies instances where a user has denied consent to an OAuth application seeking permissions within the Office 365 environment. This detection leverages O365 audit logs, focusing on events related to user consent actions. By filtering for denied consent actions associated with OAuth applications, it captures instances where users have actively rejected permission requests. This activity is significant as it may indicate users spotting potentially suspicious or unfamiliar applications. If confirmed malicious, it suggests an attempt by a potentially harmful application to gain unauthorized access, which was proactively blocked by the user.

## MITRE ATT&CK

- T1528

## Analytic Stories

- Office 365 Account Takeover

## Data Sources

- O365

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:graph:api
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1528/o365_user_consent_declined/o365_user_consent_declined.log


---

*Source: [Splunk Security Content](detections/cloud/o365_user_consent_denied_for_oauth_application.yml)*
