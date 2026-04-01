# WinEvent Scheduled Task Created to Spawn Shell

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the creation of scheduled tasks designed to execute commands using native Windows shells like PowerShell, Cmd, Wscript, or Cscript. It leverages Windows Security EventCode 4698 to identify when such tasks are registered. This activity is significant as it may indicate an attempt to establish persistence or execute malicious commands on a system. If confirmed malicious, this could allow an attacker to maintain access, execute arbitrary code, or escalate privileges, posing a severe threat to the environment.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- CISA AA22-257A
- China-Nexus Threat Activity
- Compromised Windows Host
- Medusa Ransomware
- Ransomware
- Ryuk Ransomware
- Salt Typhoon
- Scheduled Tasks
- SystemBC
- Windows Error Reporting Service Elevation of Privilege Vulnerability
- Windows Persistence Techniques
- Winter Vivern
- 0bj3ctivity Stealer
- Castle RAT

## Data Sources

- Windows Event Log Security 4698

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/winevent_scheduled_task_created_to_spawn_shell/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/winevent_scheduled_task_created_to_spawn_shell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
