# Services LOLBAS Execution Process Spawn

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies `services.exe` spawning a LOLBAS (Living Off the Land Binaries and Scripts) execution process. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where `services.exe` is the parent process. This activity is significant because adversaries often abuse the Service Control Manager to execute malicious code via native Windows binaries, facilitating lateral movement. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment, posing a severe security risk.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- Active Directory Lateral Movement
- Living Off The Land
- Qakbot
- CISA AA23-347A
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/lateral_movement_lolbas/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/services_lolbas_execution_process_spawn.yml)*
