# Windows System Time Discovery W32tm Delay

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the use of the w32tm.exe utility with the /stripchart function, which is indicative of DCRat malware delaying its payload execution. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line arguments used by w32tm.exe. This activity is significant as it may indicate an attempt to evade detection by delaying malicious actions such as C2 communication and beaconing. If confirmed malicious, this behavior could allow an attacker to maintain persistence and execute further malicious activities undetected.

## MITRE ATT&CK

- T1124

## Analytic Stories

- DarkCrystal RAT

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/dcrat_delay_execution/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_time_discovery_w32tm_delay.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
