# O365 Mailbox Folder Read Permission Assigned

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies instances where read permissions are assigned to mailbox folders within an Office 365 environment. It leverages the `o365_management_activity` data source, specifically monitoring the `ModifyFolderPermissions` and `AddFolderPermissions` operations, while excluding Calendar, Contacts, and PersonMetadata objects. This activity is significant as unauthorized read permissions can lead to data exposure and potential information leakage. If confirmed malicious, an attacker could gain unauthorized access to sensitive emails, leading to data breaches and compromising the confidentiality of organizational communications.

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

*Source: [Splunk Security Content](detections/cloud/o365_mailbox_folder_read_permission_assigned.yml)*
