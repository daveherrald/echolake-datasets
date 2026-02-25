# O365 Threat Intelligence Suspicious Email Delivered

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying when a suspicious email is detected within the Microsoft Office 365 ecosystem through the Advanced Threat Protection engine and delivered to an end user. Attackers may execute several attacks through email, any detections from built-in Office 365 capabilities should be monitored and responded to appropriately. Certain premium Office 365 capabilities such as Safe Attachment and Safe Links further enhance these detection and response functions.

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

*Source: [Splunk Security Content](detections/cloud/o365_threat_intelligence_suspicious_email_delivered.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
