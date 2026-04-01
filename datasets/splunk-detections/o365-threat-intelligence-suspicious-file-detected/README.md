# O365 Threat Intelligence Suspicious File Detected

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying when a malicious file is detected within the Microsoft Office 365 ecosystem through the Advanced Threat Protection engine. Attackers may stage and execute malicious files from within the Microsoft Office 365 ecosystem. Any detections from built-in Office 365 capabilities should be monitored and responded to appropriately. Certain premium Office 365 capabilities such as Safe Attachment and Safe Links further enhance these detection and response functions.

## MITRE ATT&CK

- T1204.002

## Analytic Stories

- Azure Active Directory Account Takeover
- Office 365 Account Takeover
- Ransomware Cloud

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/o365_various_alerts/o365_various_alerts.log


---

*Source: [Splunk Security Content](detections/cloud/o365_threat_intelligence_suspicious_file_detected.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
