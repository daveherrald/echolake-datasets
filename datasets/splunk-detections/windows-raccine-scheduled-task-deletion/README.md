# Windows Raccine Scheduled Task Deletion

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the deletion of the Raccine Rules Updater scheduled task using the `schtasks.exe` command. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because adversaries may delete this task to disable Raccine, a tool designed to prevent ransomware attacks. If confirmed malicious, this action could allow ransomware to execute without interference, leading to potential data encryption and loss.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Ransomware
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon_raccine.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_raccine_scheduled_task_deletion.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
