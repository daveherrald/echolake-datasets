# Windows Indirect Command Execution Via Series Of Forfiles

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects excessive usage of the forfiles.exe process, which is often indicative of post-exploitation activities. The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include process GUID, process name, and parent process. This activity is significant because forfiles.exe can be abused to execute commands on multiple files, a technique used by ransomware like Prestige. If confirmed malicious, this behavior could allow attackers to enumerate files, potentially leading to data exfiltration or further malicious actions.

## MITRE ATT&CK

- T1202

## Analytic Stories

- Windows Post-Exploitation
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

*Source: [Splunk Security Content](detections/endpoint/windows_indirect_command_execution_via_series_of_forfiles.yml)*
