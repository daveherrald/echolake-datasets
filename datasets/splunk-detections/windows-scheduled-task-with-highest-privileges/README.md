# Windows Scheduled Task with Highest Privileges

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of a new scheduled task with the highest execution privileges via Schtasks.exe. It leverages Endpoint Detection and Response (EDR) logs to monitor for specific command-line parameters ('/rl' and 'highest') in schtasks.exe executions. This activity is significant as it is commonly used in AsyncRAT attacks for persistence and privilege escalation. If confirmed malicious, this could allow an attacker to maintain persistent access and execute tasks with elevated privileges, potentially leading to unauthorized system access and data breaches.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- XWorm
- CISA AA23-347A
- Scheduled Tasks
- Quasar RAT
- AsyncRAT
- RedLine Stealer
- Compromised Windows Host
- Castle RAT
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/asyncrat_highest_priv_schtasks/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_scheduled_task_with_highest_privileges.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
