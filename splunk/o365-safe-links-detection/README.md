# O365 Safe Links Detection

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects when any Microsoft Safe Links alerting is triggered. This behavior may indicate when user has interacted with a phishing or otherwise malicious link within the Microsoft Office ecosystem.

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
