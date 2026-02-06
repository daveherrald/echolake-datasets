# Windows System Shutdown CommandLine

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the execution of the Windows shutdown command via the command line interface. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because attackers may use the shutdown command to erase tracks, cause disruption, or ensure changes take effect after installing backdoors. If confirmed malicious, this activity could lead to system downtime, denial of service, or evasion of security tools, impacting the overall security posture of the network.

## MITRE ATT&CK

- T1529

## Analytic Stories

- XWorm
- DarkGate Malware
- NjRAT
- Quasar RAT
- Sandworm Tools
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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/shutdown_commandline/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_shutdown_commandline.yml)*
