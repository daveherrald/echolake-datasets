# Windows Administrative Shares Accessed On Multiple Hosts

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects a source computer accessing Windows administrative shares (C$, Admin$, IPC$) on 30 or more remote endpoints within a 5-minute window. It leverages Event IDs 5140 and 5145 from file share events. This behavior is significant as it may indicate an adversary enumerating network shares to locate sensitive files, a common tactic used by threat actors. If confirmed malicious, this activity could lead to unauthorized access to critical data, lateral movement, and potential compromise of multiple systems within the network.

## MITRE ATT&CK

- T1135

## Analytic Stories

- Active Directory Privilege Escalation
- Active Directory Lateral Movement

## Data Sources

- Windows Event Log Security 5140
- Windows Event Log Security 5145

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1135/ipc_share_accessed/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_administrative_shares_accessed_on_multiple_hosts.yml)*
