# Excessive File Deletion In WinDefender Folder

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting excessive file deletion events in the Windows Defender folder. It leverages Sysmon EventCodes 23 and 26 to identify processes deleting multiple files within this directory. This behavior is significant as it may indicate an attempt to corrupt or disable Windows Defender, a key security component. If confirmed malicious, this activity could allow an attacker to disable endpoint protection, facilitating further malicious actions without detection.

## MITRE ATT&CK

- T1485

## Analytic Stories

- Data Destruction
- WhisperGate
- BlackByte Ransomware

## Data Sources

- Sysmon EventID 23
- Sysmon EventID 26

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/excessive_file_del_in_windefender_dir/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/excessive_file_deletion_in_windefender_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
