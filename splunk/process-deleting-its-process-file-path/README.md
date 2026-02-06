# Process Deleting Its Process File Path

**Type:** TTP

**Author:** Teoderick Contreras

## Description

The following analytic identifies a process attempting to delete its own file path, a behavior often associated with defense evasion techniques. This detection leverages Sysmon EventCode 1 logs, focusing on command lines executed via cmd.exe that include deletion commands. This activity is significant as it may indicate malware, such as Clop ransomware, trying to evade detection by removing its executable file if certain conditions are met. If confirmed malicious, this could allow the attacker to persist undetected, complicating incident response and remediation efforts.

## MITRE ATT&CK

- T1070

## Analytic Stories

- Clop Ransomware
- Data Destruction
- WhisperGate
- Remcos

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/process_deleting_its_process_file_path.yml)*
