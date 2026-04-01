# Windows RDP File Execution

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting when a Windows RDP client attempts to execute an RDP file from a temporary directory, downloads directory, or Outlook directories. This detection is significant as it can indicate an attempt for an adversary to deliver a .rdp file, which may be leveraged by attackers to control or exfiltrate data. If confirmed malicious, this activity could lead to unauthorized access, data theft, or further lateral movement within the network.

## MITRE ATT&CK

- T1598.002
- T1021.001

## Analytic Stories

- Spearphishing Attachments
- Windows RDP Artifacts and Defense Evasion
- Interlock Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1598.002/rdp/mstsc_rdpfile-windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rdp_file_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
