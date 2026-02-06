# Windows Scheduled Task with Suspicious Name

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects the creation, modification, or enabling of scheduled tasks with known suspicious or malicious task names. It leverages Windows Security EventCode 4698, 4700, and 4702 to identify when such tasks are registered, modified, or enabled. This activity is significant as it may indicate an attempt to establish persistence or execute malicious commands on a system. If confirmed malicious, this could allow an attacker to maintain access, execute arbitrary code, or escalate privileges, posing a severe threat to the environment.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Scheduled Tasks
- Windows Persistence Techniques
- Ransomware
- Ryuk Ransomware
- 0bj3ctivity Stealer
- APT37 Rustonotto and FadeStealer
- Castle RAT

## Data Sources

- Windows Event Log Security 4698
- Windows Event Log Security 4700
- Windows Event Log Security 4702

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/winevent_scheduled_task_with_suspect_name/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_scheduled_task_with_suspicious_name.yml)*
