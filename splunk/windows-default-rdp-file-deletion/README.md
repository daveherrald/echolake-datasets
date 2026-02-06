# Windows Default Rdp File Deletion

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies the deletion of the Default.rdp file from a user’s Documents folder. This file is automatically created or updated by the Remote Desktop Connection client (mstsc.exe) whenever a user initiates an RDP session. It contains session configuration data, such as the remote hostname and display settings. While the presence of this file is normal during legitimate RDP usage, its deletion may indicate an attempt to conceal evidence of remote access activity. Threat actors and red team operators often remove Default.rdp as part of post-access cleanup to evade forensic detection. Detecting this action—especially when correlated with recent RDP activity—can help identify defense evasion techniques and uncover potentially malicious use of remote desktop connections. Monitoring for this file's deletion adds an important layer of visibility into user behavior and can serve as an early indicator of interactive attacker presence.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.004/rdp_deletion/rdp_file_deleted.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_default_rdp_file_deletion.yml)*
