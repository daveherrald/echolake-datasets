# Wmiprvse LOLBAS Execution Process Spawn

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects `wmiprvse.exe` spawning a LOLBAS execution process. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where `wmiprvse.exe` is the parent process and the child process is a known LOLBAS binary. This activity is significant as it may indicate lateral movement or remote code execution by an adversary abusing Windows Management Instrumentation (WMI). If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment, posing a severe security risk.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Active Directory Lateral Movement

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/lateral_movement_lolbas/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/wmiprvse_lolbas_execution_process_spawn.yml)*
