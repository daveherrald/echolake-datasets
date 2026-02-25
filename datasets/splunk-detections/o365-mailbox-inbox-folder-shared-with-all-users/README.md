# O365 Mailbox Inbox Folder Shared with All Users

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting instances where the inbox folder of an Office 365 mailbox is shared with all users within the tenant. It leverages Office 365 management activity events to identify when the 'Inbox' folder permissions are modified to include 'Everyone' with read rights. This activity is significant as it represents a potential security risk, allowing unauthorized access to sensitive emails. If confirmed malicious, this could lead to data breaches, exfiltration of confidential information, and further compromise through spear-phishing or other malicious activities based on the accessed email content.

## MITRE ATT&CK

- T1114.002

## Analytic Stories

- Office 365 Persistence Mechanisms

## Data Sources

- O365 ModifyFolderPermissions

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.002/o365_inbox_shared_with_all_users/o365_inbox_shared_with_all_users.log


---

*Source: [Splunk Security Content](detections/cloud/o365_mailbox_inbox_folder_shared_with_all_users.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
