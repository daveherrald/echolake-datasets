# O365 Email Hard Delete Excessive Volume

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying when an O365 email account hard deletes an excessive number of emails within a short period (within 1 hour). This behavior may indicate a compromised account where the threat actor is attempting to permanently purge a large amount of items from the mailbox. Threat actors may attempt to remove evidence of their activity by purging items from the compromised mailbox. --- Some account owner legitimate behaviors can trigger this alert, however these actions may not be aligned with organizational expectations / best practice behaviors.

## MITRE ATT&CK

- T1070.008
- T1485

## Analytic Stories

- Office 365 Account Takeover
- Suspicious Emails
- Data Destruction

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_suspect_email_actions/o365_exchange_suspect_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_hard_delete_excessive_volume.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
