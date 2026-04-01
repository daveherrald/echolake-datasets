# Windows ConsoleHost History File Deletion

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the deletion of the ConsoleHost_history.txt file, which stores command history for PowerShell sessions. Attackers may attempt to remove this file to cover their tracks and evade detection during post-exploitation activities. This detection focuses on file deletion commands executed via PowerShell, Command Prompt, or scripting languages that specifically target ConsoleHost_history.txt, typically located at %APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt. Identifying such activity can help uncover potential anti-forensic behavior and suspicious administrative actions.

## MITRE ATT&CK

- T1070.003

## Analytic Stories

- Medusa Ransomware

## Data Sources

- Sysmon EventID 23
- Sysmon EventID 26

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.003/ConsoleHost_History_deletion/delete_pwh_history_file.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_consolehost_history_file_deletion.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
