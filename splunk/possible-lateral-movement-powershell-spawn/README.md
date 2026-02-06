# Possible Lateral Movement PowerShell Spawn

**Type:** TTP

**Author:** Mauricio Velazco, Michael Haag, Splunk

## Description

The following analytic detects the spawning of a PowerShell process as a child or grandchild of commonly abused processes like services.exe, wmiprvse.exe, svchost.exe, wsmprovhost.exe, and mmc.exe. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process names, as well as command-line executions. This activity is significant as it often indicates lateral movement or remote code execution attempts by adversaries. If confirmed malicious, this behavior could allow attackers to execute code remotely, escalate privileges, or persist within the environment.

## MITRE ATT&CK

- T1021.003
- T1021.006
- T1047
- T1053.005
- T1059.001
- T1218.014
- T1543.003

## Analytic Stories

- Active Directory Lateral Movement
- Malicious PowerShell
- Hermetic Wiper
- Data Destruction
- Scheduled Tasks
- CISA AA24-241A
- Microsoft WSUS CVE-2025-59287

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/lateral_movement_powershell/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/possible_lateral_movement_powershell_spawn.yml)*
