# Windows System Reboot CommandLine

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the execution of the Windows command line to reboot a host machine using "shutdown.exe" with specific parameters. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant as it is often associated with advanced persistent threats (APTs) and remote access trojans (RATs) like dcrat, which may use system reboots to disrupt operations, aid in system destruction, or inhibit recovery. If confirmed malicious, this could lead to system downtime, data loss, or hindered incident response efforts.

## MITRE ATT&CK

- T1529

## Analytic Stories

- XWorm
- DarkGate Malware
- NjRAT
- Quasar RAT
- DarkCrystal RAT
- MoonPeak
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/reboot_logoff_commandline/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_reboot_commandline.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
