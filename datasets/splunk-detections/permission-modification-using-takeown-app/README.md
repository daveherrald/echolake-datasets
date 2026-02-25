# Permission Modification using Takeown App

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the modification of file or directory permissions using the takeown.exe Windows application. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include process GUID, process name, and command-line details. This activity is significant because it is a common technique used by ransomware to take ownership of files or folders for encryption or deletion. If confirmed malicious, this could lead to unauthorized access, data encryption, or data destruction, severely impacting the integrity and availability of critical data.

## MITRE ATT&CK

- T1222

## Analytic Stories

- Sandworm Tools
- Ransomware
- Crypto Stealer
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/permission_modification_using_takeown_app.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
