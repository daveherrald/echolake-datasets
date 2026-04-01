# Revil Registry Entry

**Type:** TTP

**Author:** Steven Dick, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying suspicious modifications in the registry entry, specifically targeting paths used by malware like REVIL. It detects changes in registry paths such as `SOFTWARE\\WOW6432Node\\Facebook_Assistant` and `SOFTWARE\\WOW6432Node\\BlackLivesMatter`. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on registry modifications linked to process GUIDs. This activity is significant as it indicates potential malware persistence mechanisms, often used by advanced persistent threats (APTs) and ransomware. If confirmed malicious, this could allow attackers to maintain persistence, encrypt files, and store critical ransomware-related information on compromised hosts.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Ransomware
- Revil Ransomware
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 12
- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/revil_registry_entry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
