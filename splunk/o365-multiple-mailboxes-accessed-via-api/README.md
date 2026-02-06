# O365 Multiple Mailboxes Accessed via API

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects when a high number of Office 365 Exchange mailboxes are accessed via API (Microsoft Graph API or Exchange Web Services) within a short timeframe. It leverages 'MailItemsAccessed' operations in Exchange, using AppId and regex to identify API interactions. This activity is significant as it may indicate unauthorized mass email access, potentially signaling data exfiltration or account compromise. If confirmed malicious, attackers could gain access to sensitive information, leading to data breaches and further exploitation of compromised accounts. The threshold is set to flag over five unique mailboxes accessed within 10 minutes, but should be tailored to your environment.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.002/o365_multiple_mailboxes_accessed_via_api/o365_multiple_mailboxes_accessed_via_api.log


---

*Source: [Splunk Security Content](detections/cloud/o365_multiple_mailboxes_accessed_via_api.yml)*
