# Windows Rdp AutomaticDestinations Deletion

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies the deletion of files within the AutomaticDestinations folder, located under a user’s AppData\Roaming\Microsoft\Windows\Recent directory. These files are part of the Windows Jump List feature, which records recently accessed files and folders tied to specific applications. Each .automaticDestinations-ms file corresponds to a program (e.g., Explorer, Word, Notepad) and can be valuable for forensic analysis of user activity. Adversaries may target this folder to erase evidence of their actions, such as which documents or directories were accessed during a session. This type of deletion is rarely seen during normal user activity and may indicate deliberate anti-forensic behavior. When correlated with suspicious logon events, RDP usage, or script execution, this activity may represent an attempt to cover tracks after data access, lateral movement, or staging for exfiltration. Detecting removal of these artifacts can highlight post-compromise cleanup efforts and help analysts reconstruct attacker behavior.

## MITRE ATT&CK

- T1070.004

## Analytic Stories

- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 23
- Sysmon EventID 26

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.004/automatic_file_deleted/automatic_file_deleted.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rdp_automaticdestinations_deletion.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
