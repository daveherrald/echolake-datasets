# Windows Known Abused DLL Created

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying the creation of Dynamic Link Libraries (DLLs) with a known history of exploitation in atypical locations. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and filesystem events. This activity is significant as it may indicate DLL search order hijacking or sideloading, techniques used by attackers to execute arbitrary code, maintain persistence, or escalate privileges. If confirmed malicious, this activity could allow attackers to blend in with legitimate operations, posing a severe threat to system integrity and security.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Living Off The Land

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.002/hijacklibs/hijacklibs_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_known_abused_dll_created.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
