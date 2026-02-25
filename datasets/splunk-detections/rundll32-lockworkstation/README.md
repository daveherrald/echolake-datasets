# Rundll32 LockWorkStation

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the rundll32.exe command with the user32.dll,LockWorkStation parameter, which is used to lock the workstation via command line. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it is an uncommon method to lock a screen and has been observed in CONTI ransomware tooling for defense evasion. If confirmed malicious, this technique could indicate an attempt to evade detection and hinder incident response efforts.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/conti/conti_leak/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rundll32_lockworkstation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
