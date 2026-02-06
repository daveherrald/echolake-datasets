# Detect Prohibited Applications Spawning cmd exe

**Type:** Hunting

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects executions of cmd.exe spawned by processes that are commonly abused by attackers and do not typically launch cmd.exe. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process GUID, process name, parent process, and command-line executions. This activity is significant because it may indicate an attempt to execute unauthorized commands or scripts, often a precursor to further malicious actions. If confirmed malicious, this behavior could lead to unauthorized code execution, privilege escalation, or persistence within the environment.

## MITRE ATT&CK

- T1059.003

## Analytic Stories

- Suspicious Command-Line Executions
- Suspicious MSHTA Activity
- Suspicious Zoom Child Processes
- NOBELIUM Group

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/powershell_spawn_cmd/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_prohibited_applications_spawning_cmd_exe.yml)*
