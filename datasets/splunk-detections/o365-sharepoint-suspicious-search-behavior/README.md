# O365 SharePoint Suspicious Search Behavior

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying when Office 365 users search for suspicious keywords or have an excessive number of queries to a SharePoint site within a limited timeframe. This behavior may indicate that a malicious actor has gained control of a user account and is conducting discovery or enumeration activities.

## MITRE ATT&CK

- T1213.002
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

*Source: [Splunk Security Content](detections/cloud/o365_sharepoint_suspicious_search_behavior.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
