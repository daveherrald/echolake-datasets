# O365 Email Security Feature Changed

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic identifies when specific O365 advanced security settings are altered within the Office 365 tenant. If an attacker successfully disables O365 security settings, they can operate within the tenant with reduced risk of detection. This can lead to unauthorized data access, data exfiltration, account compromise, or other malicious activities without leaving a detailed audit trail.

## MITRE ATT&CK

- T1562.001
- T1562.008

## Analytic Stories

- Office 365 Persistence Mechanisms
- Office 365 Account Takeover

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/o365_various_alerts/o365_various_alerts.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_security_feature_changed.yml)*
