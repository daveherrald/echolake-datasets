# O365 Exfiltration via File Sync Download

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic detects when an excessive number of files are sync from o365 by the same user over a short period of time. A malicious actor abuse the user-agent string through GUI or API access to evade triggering the FileDownloaded event. This behavior may indicate an attacker staging data for exfiltration or an insider threat removing organizational data. Additional attention should be taken with any Azure Guest (#EXT#) accounts.

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

*Source: [Splunk Security Content](detections/cloud/o365_exfiltration_via_file_sync_download.yml)*
