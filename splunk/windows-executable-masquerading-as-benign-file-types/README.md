# Windows Executable Masquerading as Benign File Types

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the presence of executable files masquerading as benign file types on Windows systems. Adversaries employ this technique to evade defenses and trick users into executing malicious code by renaming executables with extensions commonly associated with documents, images, or other non-executable formats (e.g., .pdf, .jpg, .doc, .png).


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
