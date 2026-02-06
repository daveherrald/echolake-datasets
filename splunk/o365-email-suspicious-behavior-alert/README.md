# O365 Email Suspicious Behavior Alert

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic identifies when one of O365 the built-in security detections for suspicious email behaviors are triggered.  These alerts often indicate that an attacker may have compromised a mailbox within the environment. Any detections from built-in Office 365 capabilities should be monitored and responded to appropriately. Certain premium Office 365 capabilities further enhance these detection and response functions.

## MITRE ATT&CK

- T1114.003

## Analytic Stories

- Suspicious Emails
- Office 365 Collection Techniques
- Office 365 Account Takeover

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/o365_various_alerts/o365_various_alerts.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_suspicious_behavior_alert.yml)*
