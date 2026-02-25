# O365 Email Send and Hard Delete Exfiltration Behavior

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying when an O365 email account sends and then hard deletes an email to an external recipient within a short period (within 1 hour). This behavior may indicate a compromised account where the threat actor is attempting to remove forensic artifacts or evidence of exfiltration activity. This behavior is often seen when threat actors want to reduce the probability of detection by the compromised account owner.

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
- Office 365 Reporting Message Trace

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_suspect_email_actions/o365_exchange_suspect_events.log

- **Source:** o365_messagetrace
  **Sourcetype:** o365:reporting:messagetrace
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_suspect_email_actions/o365_messagetrace_suspect_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_send_and_hard_delete_exfiltration_behavior.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
