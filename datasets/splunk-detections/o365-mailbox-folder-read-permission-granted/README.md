# O365 Mailbox Folder Read Permission Granted

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying instances where read permissions are granted to mailbox folders within an Office 365 environment. It detects this activity by monitoring the `o365_management_activity` data source for the `Set-MailboxFolderPermission` and `Add-MailboxFolderPermission` operations. This behavior is significant as it may indicate unauthorized access or changes to mailbox folder permissions, potentially exposing sensitive email content. If confirmed malicious, an attacker could gain unauthorized access to read email communications, leading to data breaches or information leakage.

## MITRE ATT&CK

- T1098.002

## Analytic Stories

- Office 365 Collection Techniques

## Data Sources

- O365 ModifyFolderPermissions

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.002/o365_mailbox_folder_read_granted/o365_mailbox_folder_read_granted.log


---

*Source: [Splunk Security Content](detections/cloud/o365_mailbox_folder_read_permission_granted.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
