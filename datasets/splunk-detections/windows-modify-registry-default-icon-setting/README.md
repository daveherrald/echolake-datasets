# Windows Modify Registry Default Icon Setting

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious modifications to the Windows registry's default icon settings, a technique associated with Lockbit ransomware. It leverages data from the Endpoint Registry data model, focusing on changes to registry paths under "*HKCR\\*\\defaultIcon\\(Default)*". This activity is significant as it is uncommon for normal users to modify these settings, and such changes can indicate ransomware infection or other malware. If confirmed malicious, this could lead to system defacement and signal a broader ransomware attack, potentially compromising sensitive data and system integrity.

## MITRE ATT&CK

- T1112

## Analytic Stories

- LockBit Ransomware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/lockbit_ransomware/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_default_icon_setting.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
