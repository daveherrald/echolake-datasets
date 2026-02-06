# O365 Email Suspicious Search Behavior

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic identifies when Office 365 users search for suspicious keywords or have an excessive number of queries to a mailbox within a limited timeframe. This behavior may indicate that a malicious actor has gained control of a mailbox and is conducting discovery or enumeration activities.

## MITRE ATT&CK

- T1114.002
- T1552

## Analytic Stories

- Office 365 Account Takeover
- Office 365 Collection Techniques
- Compromised User Account
- CISA AA22-320A

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1213.002/o365_sus_sharepoint_search/o365_sus_sharepoint_search.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_suspicious_search_behavior.yml)*
