# Scheduled Task Creation on Remote Endpoint using At

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the creation of scheduled tasks on remote Windows endpoints using the at.exe command. This detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process creation events involving at.exe with remote command-line arguments. Identifying this activity is significant for a SOC as it may indicate lateral movement or remote code execution attempts by an attacker. If confirmed malicious, this activity could lead to unauthorized access, persistence, or execution of malicious code, potentially resulting in data theft or further compromise of the network.

## MITRE ATT&CK

- T1053.002

## Analytic Stories

- Active Directory Lateral Movement
- Living Off The Land
- Scheduled Tasks
- 0bj3ctivity Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.002/lateral_movement/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/scheduled_task_creation_on_remote_endpoint_using_at.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
