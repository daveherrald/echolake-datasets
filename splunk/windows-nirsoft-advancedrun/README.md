# Windows NirSoft AdvancedRun

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of AdvancedRun.exe, a tool with capabilities similar to remote administration programs like PsExec. It identifies the process by its name or original file name and flags common command-line arguments. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line telemetry. Monitoring this activity is crucial as AdvancedRun can be used for remote code execution and configuration-based automation. If malicious, this could allow attackers to execute arbitrary commands, escalate privileges, or maintain persistence within the environment.

## MITRE ATT&CK

- T1588.002

## Analytic Stories

- Ransomware
- Unusual Processes
- Data Destruction
- WhisperGate

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1588.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_nirsoft_advancedrun.yml)*
