# Scheduled Task Initiation on Remote Endpoint

**Type:** TTP

**Author:** Mauricio Velazco, Splunk, Badoodish, Github Community

## Description

This dataset contains sample data for detecting the use of 'schtasks.exe' to start a Scheduled Task on a remote endpoint. This detection leverages Endpoint Detection and Response (EDR) data, focusing on process details such as process name, parent process, and command-line executions. This activity is significant as adversaries often abuse Task Scheduler for lateral movement and remote code execution. If confirmed malicious, this behavior could allow attackers to execute arbitrary code remotely, potentially leading to further compromise of the network.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Living Off The Land
- Active Directory Lateral Movement
- Scheduled Tasks
- Medusa Ransomware
- Seashell Blizzard

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/lateral_movement/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/scheduled_task_initiation_on_remote_endpoint.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
