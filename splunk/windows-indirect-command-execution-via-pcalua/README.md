# Windows Indirect Command Execution Via pcalua

**Type:** TTP

**Author:** Eric McGinnis, Splunk

## Description

The following analytic detects programs initiated by pcalua.exe, the Microsoft Windows Program Compatibility Assistant. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process information. While pcalua.exe can start legitimate programs, it is significant because attackers may use it to bypass command line execution protections. If confirmed malicious, this activity could allow attackers to execute arbitrary commands, potentially leading to unauthorized actions, privilege escalation, or persistence within the environment.

## MITRE ATT&CK

- T1202

## Analytic Stories

- Living Off The Land

## Data Sources

- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1202/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_indirect_command_execution_via_pcalua.yml)*
