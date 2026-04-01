# Disabling FolderOptions Windows Feature

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting the modification of the Windows registry to disable the Folder Options feature, which prevents users from showing hidden files and file extensions. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFolderOptions" with a value of "0x00000001". This activity is significant as it is commonly used by malware to conceal malicious files and deceive users with fake file extensions. If confirmed malicious, this could allow an attacker to hide their presence and malicious files, making detection and remediation more difficult.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- CISA AA23-347A
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disabling_folderoptions_windows_feature.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
