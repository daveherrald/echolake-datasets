# O365 OAuth App Mailbox Access via Graph API

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects when emails are accessed in Office 365 Exchange via the Microsoft Graph API using the client ID '00000003-0000-0000-c000-000000000000'. It leverages the 'MailItemsAccessed' operation within the Exchange workload, focusing on OAuth-authenticated applications. This activity is significant as unauthorized access to emails can lead to data breaches and information theft. If confirmed malicious, attackers could exfiltrate sensitive information, compromise user accounts, and further infiltrate the organization's network.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.002/o365_oauth_app_graph_mailbox_access/o365_oauth_app_graph_mailbox_access.log


---

*Source: [Splunk Security Content](detections/cloud/o365_oauth_app_mailbox_access_via_graph_api.yml)*
