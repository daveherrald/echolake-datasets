# O365 Exfiltration via File Access

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting when an excessive number of files are access from o365 by the same user over a short period of time. A malicious actor may abuse the "open in app" functionality of SharePoint through scripted or Graph API based access to evade triggering the FileDownloaded Event. This behavior may indicate an attacker staging data for exfiltration or an insider threat removing organizational data. Additional attention should be take with any Azure Guest (#EXT#) accounts.

## MITRE ATT&CK

- T1567
- T1530

## Analytic Stories

- Data Exfiltration
- Office 365 Account Takeover

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1567/o365_sus_file_activity/o365_sus_file_activity.log


---

*Source: [Splunk Security Content](detections/cloud/o365_exfiltration_via_file_access.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
