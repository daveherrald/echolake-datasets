# Windows Scheduled Task with Suspicious Command

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting the creation of scheduled tasks designed to execute commands using native Windows shells like PowerShell, Cmd, Wscript, or Cscript or from public folders such as Users, Temp, or ProgramData. It leverages Windows Security EventCode 4698, 4700, and 4702 to identify when such tasks are registered, enabled, or modified. This activity is significant as it may indicate an attempt to establish persistence or execute malicious commands on a system. If confirmed malicious, this could allow an attacker to maintain access, execute arbitrary code, or escalate privileges, posing a severe threat to the environment.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Scheduled Tasks
- Ransomware
- Quasar RAT
- Ryuk Ransomware
- Windows Persistence Techniques
- Seashell Blizzard
- APT37 Rustonotto and FadeStealer

## Data Sources

- Windows Event Log Security 4698
- Windows Event Log Security 4700
- Windows Event Log Security 4702

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/winevent_scheduled_task_created_to_spawn_shell/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_scheduled_task_with_suspicious_command.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
