# O365 ZAP Activity Detection

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting when the Microsoft Zero-hour Automatic Purge (ZAP) capability takes action against a user's mailbox. This capability is an enhanced protection feature that retro-actively removes email with known malicious content for user inboxes. Since this is a retroactive capability, there is still a window in which the user may fall victim to the malicious content.

## MITRE ATT&CK

- T1566.001
- T1566.002

## Analytic Stories

- Spearphishing Attachments
- Suspicious Emails

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/o365_various_alerts/o365_various_alerts.log


---

*Source: [Splunk Security Content](detections/cloud/o365_zap_activity_detection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
