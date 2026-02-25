# Windows PaperCut NG Spawn Shell

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting instances where the PaperCut NG application (pc-app.exe) spawns a Windows shell, such as cmd.exe or PowerShell. This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on process creation events where the parent process is pc-app.exe. This activity is significant as it may indicate an attacker attempting to gain unauthorized access or execute malicious commands on the system. If confirmed malicious, this could lead to unauthorized code execution, privilege escalation, or further compromise of the affected environment.

## MITRE ATT&CK

- T1059
- T1190
- T1133

## Analytic Stories

- PaperCut MF NG Vulnerability
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/papercut/papercutng-app-spawn_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_papercut_ng_spawn_shell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
