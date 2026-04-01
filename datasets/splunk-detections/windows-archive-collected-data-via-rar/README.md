# Windows Archive Collected Data via Rar

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the execution of RAR utilities to archive files on a system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, GUIDs, and command-line arguments. This activity is significant as threat actors, including red-teamers and malware like DarkGate, use RAR archiving to compress and exfiltrate collected data from compromised hosts. If confirmed malicious, this behavior could lead to the unauthorized transfer of sensitive information to command and control servers, posing a severe risk to data confidentiality and integrity.

## MITRE ATT&CK

- T1560.001

## Analytic Stories

- DarkGate Malware
- Salt Typhoon
- China-Nexus Threat Activity
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility_darkgate/rar_sys.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_archive_collected_data_via_rar.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
