# Windows Modify Registry LongPathsEnabled

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a modification to the Windows registry setting "LongPathsEnabled," which allows file paths longer than 260 characters. This detection leverages data from the Endpoint.Registry datamodel, focusing on changes to the specific registry path and value. This activity is significant because adversaries, including malware like BlackByte, exploit this setting to bypass file path limitations, potentially aiding in evasion techniques. If confirmed malicious, this modification could facilitate the execution of long-path payloads, aiding in persistence and further system compromise.

## MITRE ATT&CK

- T1112

## Analytic Stories

- BlackByte Ransomware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/blackbyte/longpathsenabled/longpath_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_longpathsenabled.yml)*
