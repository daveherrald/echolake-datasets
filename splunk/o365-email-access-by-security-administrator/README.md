# O365 Email Access By Security Administrator

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic identifies when a user with sufficient access to O365 Security & Compliance portal uses premium investigation features (Threat Explorer) to directly view email. Adversaries may exploit privileged access with this premium feature to enumerate or exfiltrate sensitive data.

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
