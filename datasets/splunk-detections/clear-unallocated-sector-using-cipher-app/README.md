# Clear Unallocated Sector Using Cipher App

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of `cipher.exe` with the `/w` flag to clear unallocated sectors on a disk. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, command-line arguments, and parent processes. This activity is significant because it is a technique used by ransomware to prevent forensic recovery of deleted files. If confirmed malicious, this action could hinder incident response efforts by making it impossible to recover critical data, thereby complicating the investigation and remediation process.

## MITRE ATT&CK

- T1070.004

## Analytic Stories

- Ransomware
- Compromised Windows Host
- Scattered Spider

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/clear_unallocated_sector_using_cipher_app.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
