# Windows MSTSC RDP Commandline

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of the mstsc.exe command-line, which is commonly used to initiate Remote Desktop Protocol (RDP) connections. This detection focuses on instances where mstsc.exe is executed with specific parameters that may indicate suspicious or unauthorized remote access attempts. Monitoring command-line arguments such as /v:<target> for direct connections or /admin for administrative sessions can help identify potential misuse or lateral movement within a network.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Medusa Ransomware
- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.001/mstsc_rdp_cmd/mstsc_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_mstsc_rdp_commandline.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
