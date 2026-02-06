# Windows File Collection Via Copy Utilities

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of Windows command-line copy utilities, such as xcopy, to systematically collect files from user directories and consolidate them into a centralized location on the system. This activity is often indicative of malicious behavior, as threat actors frequently use such commands to gather sensitive information, including documents with .doc, .docx, and .pdf extensions. The detection focuses on identifying recursive copy operations targeting user folders, such as Documents, Desktop, or other directories that commonly store personal or organizational files. Malware that performs this behavior typically attempts to evade detection by using legitimate Windows utilities, executing commands through cmd.exe or other scripting hosts, and writing the collected files to directories like C:\ProgramData or temporary storage locations. Once collected, the information may be staged for exfiltration, used for lateral movement, or leveraged for further compromise of the environment. By monitoring for these types of file collection patterns, security teams can identify suspicious activity early, differentiate between normal administrative tasks and potentially malicious scripts, and prevent sensitive data from being exfiltrated. This analytic is particularly relevant for environments where confidential documents are present and attackers may attempt to harvest them using built-in Windows tools.

## MITRE ATT&CK

- T1119

## Analytic Stories

- LAMEHUG

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/lamehug/T1119/doc_collection/xcopy_event.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_file_collection_via_copy_utilities.yml)*
