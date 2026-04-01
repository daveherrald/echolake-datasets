# Windows MSExchange Management Mailbox Cmdlet Usage

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying suspicious Cmdlet usage in Exchange Management logs, focusing on commands like New-MailboxExportRequest and New-ManagementRoleAssignment. It leverages EventCode 1 and specific Message patterns to detect potential ProxyShell and ProxyNotShell abuse. This activity is significant as it may indicate unauthorized access or manipulation of mailboxes and roles, which are critical for maintaining email security. If confirmed malicious, attackers could export mailbox data, assign new roles, or search mailboxes, leading to data breaches and privilege escalation.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- ProxyShell
- BlackByte Ransomware
- ProxyNotShell
- Scattered Spider

## Data Sources


## Sample Data

- **Source:** WinEventLog:MSExchange Management
  **Sourcetype:** MSExchange:management
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/exchange/msexchangemanagement.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_msexchange_management_mailbox_cmdlet_usage.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
