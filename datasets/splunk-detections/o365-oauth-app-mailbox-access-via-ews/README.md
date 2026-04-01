# O365 OAuth App Mailbox Access via EWS

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting when emails are accessed in Office 365 Exchange via Exchange Web Services (EWS) using OAuth-authenticated applications. It leverages the ClientInfoString field to identify EWS interactions and aggregates metrics such as access counts, timing, and client IP addresses, categorized by user, ClientAppId, OperationCount, and AppId. Monitoring OAuth applications accessing emails through EWS is crucial for identifying potential abuse or unauthorized data access. If confirmed malicious, this activity could lead to unauthorized email access, data exfiltration, or further compromise of sensitive information.

## MITRE ATT&CK

- T1114.002

## Analytic Stories

- Office 365 Collection Techniques
- NOBELIUM Group

## Data Sources

- O365 MailItemsAccessed

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.002/o365_oauth_app_ews_mailbox_access/o365_oauth_app_ews_mailbox_access.log


---

*Source: [Splunk Security Content](detections/cloud/o365_oauth_app_mailbox_access_via_ews.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
