# Windows Registry Entries Exported Via Reg

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the reg.exe process with either the "save" or "export" parameters. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. This activity is significant because threat actors often use the "reg save" or "reg export" command to dump credentials or test registry modification capabilities on compromised hosts. If confirmed malicious, this behavior could allow attackers to escalate privileges, persist in the environment, or access sensitive information stored in the registry.

## MITRE ATT&CK

- T1012

## Analytic Stories

- Windows Post-Exploitation
- CISA AA23-347A
- Prestige Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_registry_entries_exported_via_reg.yml)*
