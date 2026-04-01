# O365 Safe Links Detection

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting when any Microsoft Safe Links alerting is triggered. This behavior may indicate when user has interacted with a phishing or otherwise malicious link within the Microsoft Office ecosystem.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Office 365 Account Takeover
- Spearphishing Attachments

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/o365_various_alerts/o365_various_alerts.log


---

*Source: [Splunk Security Content](detections/cloud/o365_safe_links_detection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
