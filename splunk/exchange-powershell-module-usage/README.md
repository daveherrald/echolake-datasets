# Exchange PowerShell Module Usage

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the usage of specific Exchange PowerShell modules, such as New-MailboxExportRequest, New-ManagementRoleAssignment, New-MailboxSearch, and Get-Recipient. It leverages PowerShell Script Block Logging (EventCode 4104) to identify these commands. This activity is significant because these modules can be exploited by adversaries who have gained access via ProxyShell or ProxyNotShell vulnerabilities. If confirmed malicious, attackers could export mailbox contents, assign management roles, conduct mailbox searches, or view recipient objects, potentially leading to data exfiltration, privilege escalation, or unauthorized access to sensitive information.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- ProxyNotShell
- CISA AA22-277A
- ProxyShell
- BlackByte Ransomware
- CISA AA22-264A
- Scattered Spider

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/exchange/windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/exchange_powershell_module_usage.yml)*
