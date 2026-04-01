# Windows Executable Masquerading as Benign File Types

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the presence of executable files masquerading as benign file types on Windows systems. Adversaries employ this technique to evade defenses and trick users into executing malicious code by renaming executables with extensions commonly associated with documents, images, or other non-executable formats (e.g., .pdf, .jpg, .doc, .png).


## MITRE ATT&CK

- T1036.008

## Analytic Stories

- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 29

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.008/masquerading_executable_as_non_exec_file_type/non_exec_ext_but_exec_detected.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_executable_masquerading_as_benign_file_types.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
