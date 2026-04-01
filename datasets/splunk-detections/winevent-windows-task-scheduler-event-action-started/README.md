# WinEvent Windows Task Scheduler Event Action Started

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of tasks registered in Windows Task Scheduler by monitoring EventID 200 (action run) and 201 (action completed) from the Task Scheduler logs. This detection leverages Task Scheduler logs to identify potentially suspicious or unauthorized task executions. Monitoring these events is significant for a SOC as it helps uncover evasive techniques used for persistence, unauthorized code execution, or other malicious activities. If confirmed malicious, this activity could lead to unauthorized access, data exfiltration, or the execution of harmful payloads, posing a significant threat to the environment.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- IcedID
- BlackSuit Ransomware
- Windows Persistence Techniques
- Prestige Ransomware
- Winter Vivern
- CISA AA22-257A
- Amadey
- AsyncRAT
- ValleyRAT
- SystemBC
- Malicious Inno Setup Loader
- Scheduled Tasks
- Data Destruction
- CISA AA24-241A
- DarkCrystal RAT
- Qakbot
- Sandworm Tools
- Industroyer2
- PlugX
- Remcos

## Data Sources

- Windows Event Log TaskScheduler 200
- Windows Event Log TaskScheduler 201

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/winevent_windows_task_scheduler_event_action_started/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/winevent_windows_task_scheduler_event_action_started.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
