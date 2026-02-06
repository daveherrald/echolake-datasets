# O365 Email Send and Hard Delete Suspicious Behavior

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic identifies when an O365 email account sends and then hard deletes email with within a short period (within 1 hour). This behavior may indicate a compromised account where the threat actor is attempting to remove forensic artifacts or evidence of activity. Threat actors often use this technique to prevent defenders and victims from knowing the account has been compromised. --- Some account owner legitimate behaviors can trigger this alert, however these actions may not be aligned with organizational expectations / best practice behaviors.

## MITRE ATT&CK

- T1114.001
- T1070.008
- T1485

## Analytic Stories

- Office 365 Account Takeover
- Office 365 Collection Techniques
- Suspicious Emails
- Data Destruction

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_suspect_email_actions/o365_exchange_suspect_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_send_and_hard_delete_suspicious_behavior.yml)*
