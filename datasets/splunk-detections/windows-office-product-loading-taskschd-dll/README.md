# Windows Office Product Loading Taskschd DLL

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting an Office document creating a scheduled task, either through a macro VBA API or by loading `taskschd.dll`. This detection leverages Sysmon EventCode 7 to identify when Office applications load the `taskschd.dll` file. This activity is significant as it is a common technique used by malicious macro malware to establish persistence or initiate beaconing. If confirmed malicious, this could allow an attacker to maintain persistence, execute arbitrary commands, or schedule future malicious activities, posing a significant threat to the environment.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_office_product_loading_taskschd_dll.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
