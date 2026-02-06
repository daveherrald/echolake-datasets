# Windows Default Rdp File Unhidden

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies the use of attrib.exe to remove hidden (-h) or system (-s) attributes from the Default.rdp file, which is automatically created in a user's Documents folder when a Remote Desktop Protocol (RDP) session is initiated using mstsc.exe. The Default.rdp file stores session configuration details such as the remote host address and screen settings. Unhiding this file is uncommon in normal user behavior and may indicate that an attacker or red team operator is attempting to access or manipulate RDP connection history that was previously hidden—either by default or as part of an earlier anti-forensics effort. This activity may represent part of a broader pattern of reconnaissance or staging for credential reuse, lateral movement, or forensic analysis evasion. Monitoring for this behavior can help uncover suspicious manipulation of user artifacts and highlight interactive attacker activity on a compromised host.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.001/unhide_file/unhide_file.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_default_rdp_file_unhidden.yml)*
