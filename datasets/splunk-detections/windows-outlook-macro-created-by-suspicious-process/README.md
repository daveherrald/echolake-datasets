# Windows Outlook Macro Created by Suspicious Process

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This dataset contains sample data for detecting the creation of an Outlook Macro (VbaProject.OTM) by a suspicious process. This file is normally created when you create a macro from within Outlook. If this file is created by a process other than Outlook.exe it may be maliciously created. This detection leverages data from the Filesystem datamodel, specifically looking for the file creation event for VbaProject.OTM. This activity is significant as it is commonly associated with some malware infections, indicating potential malicious intent to harvest email information.

## MITRE ATT&CK

- T1137
- T1059.005

## Analytic Stories

- NotDoor Malware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/notdoor/outlook_macro/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_outlook_macro_created_by_suspicious_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
