# Windows CAB File on Disk

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects .cab files being written to disk. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on events where the file name is '*.cab' and the action is 'write'. This activity is significant as .cab files can be used to deliver malicious payloads, including embedded .url files that execute harmful code. If confirmed malicious, this behavior could lead to unauthorized code execution and potential system compromise. Analysts should review the file path and associated artifacts for further investigation.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- DarkGate Malware
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/autoit/cab_files.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_cab_file_on_disk.yml)*
