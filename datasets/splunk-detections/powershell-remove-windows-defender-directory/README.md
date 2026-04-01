# Powershell Remove Windows Defender Directory

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious PowerShell command attempting to delete the Windows Defender directory. It leverages PowerShell Script Block Logging to identify commands containing "rmdir" and targeting the Windows Defender path. This activity is significant as it may indicate an attempt to disable or corrupt Windows Defender, a key security component. If confirmed malicious, this action could allow an attacker to bypass endpoint protection, facilitating further malicious activities without detection.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Data Destruction
- WhisperGate

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_remove_windows_defender_directory.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
