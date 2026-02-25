# O365 Email Access By Security Administrator

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying when a user with sufficient access to O365 Security & Compliance portal uses premium investigation features (Threat Explorer) to directly view email. Adversaries may exploit privileged access with this premium feature to enumerate or exfiltrate sensitive data.

## MITRE ATT&CK

- T1114.002
- T1567

## Analytic Stories

- Data Exfiltration
- Azure Active Directory Account Takeover
- Office 365 Account Takeover

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/o365_various_alerts/o365_various_alerts.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_access_by_security_administrator.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
