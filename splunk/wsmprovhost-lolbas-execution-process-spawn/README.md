# Wsmprovhost LOLBAS Execution Process Spawn

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies `Wsmprovhost.exe` spawning a LOLBAS execution process. It leverages Endpoint Detection and Response (EDR) data to detect when `Wsmprovhost.exe` spawns child processes that are known LOLBAS (Living Off the Land Binaries and Scripts) executables. This activity is significant because it may indicate an adversary using Windows Remote Management (WinRM) to execute code on remote endpoints, a common technique for lateral movement. If confirmed malicious, this could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment.

## MITRE ATT&CK

- T1021.006

## Analytic Stories

- Active Directory Lateral Movement
- CISA AA24-241A
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/lateral_movement_lolbas/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/wsmprovhost_lolbas_execution_process_spawn.yml)*
