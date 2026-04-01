# Execution of File with Multiple Extensions

**Type:** TTP

**Author:** Rico Valdez, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of files with multiple extensions, such as ".doc.exe" or ".pdf.exe". This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on process creation events where the file name contains double extensions. This activity is significant because attackers often use double extensions to disguise malicious executables as benign documents, increasing the likelihood of user execution. If confirmed malicious, this technique can lead to unauthorized code execution, potentially compromising the endpoint and allowing further malicious activities.

## MITRE ATT&CK

- T1036.003

## Analytic Stories

- Windows File Extension and Association Abuse
- Masquerading - Rename System Utilities
- AsyncRAT
- DarkGate Malware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/execution_of_file_with_multiple_extensions.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
