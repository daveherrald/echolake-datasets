# WinEvent Scheduled Task Created Within Public Path

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation of scheduled tasks within user-writable paths using Windows Security EventCode 4698. It identifies tasks registered via schtasks.exe or TaskService that execute commands from directories like Public, ProgramData, Temp, and AppData. This behavior is significant as it may indicate an attempt to establish persistence or execute unauthorized commands. If confirmed malicious, an attacker could maintain long-term access, escalate privileges, or execute arbitrary code, posing a severe threat to system integrity and security.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Data Destruction
- Winter Vivern
- Industroyer2
- Compromised Windows Host
- Quasar RAT
- China-Nexus Threat Activity
- XWorm
- Ransomware
- IcedID
- CISA AA23-347A
- Salt Typhoon
- Ryuk Ransomware
- Active Directory Lateral Movement
- Malicious Inno Setup Loader
- CISA AA22-257A
- Medusa Ransomware
- SystemBC
- Scheduled Tasks
- Prestige Ransomware
- AsyncRAT
- Windows Persistence Techniques
- 0bj3ctivity Stealer
- APT37 Rustonotto and FadeStealer
- Castle RAT
- ValleyRAT
- PlugX
- Remcos

## Data Sources

- Windows Event Log Security 4698

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/winevent_scheduled_task_created_to_spawn_shell/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/winevent_scheduled_task_created_within_public_path.yml)*
