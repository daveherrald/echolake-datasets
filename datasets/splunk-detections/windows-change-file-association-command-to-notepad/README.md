# Windows Change File Association Command To Notepad

**Type:** TTP

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting attempts to change the command value of a file association of an extension to open with Notepad.exe.
It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line patterns and registry modifications.
This activity is significant as it can indicate an attempt to manipulate file handling behavior, a technique observed in APT and ransomware attacks like Prestige.
After changing the extension of all encrypted files to a new one, Prestige ransomware modifies the file association for that extension to open with Notepad.exe in order to display a ransom note.


## MITRE ATT&CK

- T1546.001

## Analytic Stories

- Prestige Ransomware
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/prestige_ransomware/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_change_file_association_command_to_notepad.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
