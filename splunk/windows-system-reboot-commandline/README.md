# Windows System Reboot CommandLine

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the execution of the Windows command line to reboot a host machine using "shutdown.exe" with specific parameters. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant as it is often associated with advanced persistent threats (APTs) and remote access trojans (RATs) like dcrat, which may use system reboots to disrupt operations, aid in system destruction, or inhibit recovery. If confirmed malicious, this could lead to system downtime, data loss, or hindered incident response efforts.

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
