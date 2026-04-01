# Short Lived Scheduled Task

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the creation and deletion of scheduled tasks within a short time frame (less than 30 seconds) using Windows Security EventCodes 4698 and 4699. This behavior is identified by analyzing Windows Security Event Logs and leveraging the Windows TA for parsing. Such activity is significant as it may indicate lateral movement or remote code execution attempts by adversaries. If confirmed malicious, this could lead to unauthorized access, data exfiltration, or execution of malicious payloads, necessitating prompt investigation and response by security analysts.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Active Directory Lateral Movement
- CISA AA22-257A
- CISA AA23-347A
- Compromised Windows Host
- Scheduled Tasks

## Data Sources

- Windows Event Log Security 4698
- Windows Event Log Security 4699

## Sample Data

- **Source:** WinEventLog:Security
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/lateral_movement/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/short_lived_scheduled_task.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
