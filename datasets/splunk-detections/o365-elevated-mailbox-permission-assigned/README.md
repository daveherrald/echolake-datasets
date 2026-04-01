# O365 Elevated Mailbox Permission Assigned

**Type:** TTP

**Author:** Patrick Bareiss, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the assignment of elevated mailbox permissions in an Office 365 environment via the Add-MailboxPermission operation. It leverages logs from the Exchange workload in the o365_management_activity data source, focusing on permissions such as FullAccess, ChangePermission, or ChangeOwner. This activity is significant as it indicates potential unauthorized access or control over mailboxes, which could lead to data exfiltration or privilege escalation. If confirmed malicious, attackers could gain extensive access to sensitive email data and potentially manipulate mailbox settings, posing a severe security risk.

## MITRE ATT&CK

- T1098.002

## Analytic Stories

- Office 365 Collection Techniques

## Data Sources

- O365 Add-MailboxPermission

## Sample Data

- **Source:** o365:management:activity
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.002/suspicious_rights_delegation/suspicious_rights_delegation.json


---

*Source: [Splunk Security Content](detections/cloud/o365_elevated_mailbox_permission_assigned.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
