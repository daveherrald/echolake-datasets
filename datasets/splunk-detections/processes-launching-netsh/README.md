# Processes launching netsh

**Type:** Anomaly

**Author:** Michael Haag, Josef Kuepker, Splunk

## Description

This dataset contains sample data for identifying processes launching netsh.exe, a command-line utility used to modify network configurations. It detects this activity by analyzing data from Endpoint Detection and Response (EDR) agents, focusing on process GUIDs, names, parent processes, and command-line executions. This behavior is significant because netsh.exe can be exploited to execute malicious helper DLLs, serving as a persistence mechanism. If confirmed malicious, an attacker could gain persistent access, modify network settings, and potentially escalate privileges, posing a severe threat to the network's integrity and security.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- Netsh Abuse
- Disabling Security Tools
- DHS Report TA18-074A
- Azorult
- Volt Typhoon
- Snake Keylogger
- ShrinkLocker
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/processes_launching_netsh.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
