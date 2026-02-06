# Detect Use of cmd exe to Launch Script Interpreters

**Type:** TTP

**Author:** Bhavin Patel, Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of cscript.exe or wscript.exe processes initiated by cmd.exe. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and parent processes within the Endpoint data model. This activity is significant as it may indicate script-based attacks or administrative actions that could be leveraged for malicious purposes. If confirmed malicious, this behavior could allow attackers to execute scripts, potentially leading to code execution, privilege escalation, or persistence within the environment.

## MITRE ATT&CK

- T1059.003

## Analytic Stories

- Emotet Malware DHS Report TA18-201A
- Suspicious Command-Line Executions
- Azorult

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/cmd_spawns_cscript/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_use_of_cmd_exe_to_launch_script_interpreters.yml)*
