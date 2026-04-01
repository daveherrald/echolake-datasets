# Suspicious Reg exe Process

**Type:** Anomaly

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for identifying instances of reg.exe being launched from a command prompt (cmd.exe) that was not initiated by the user, as indicated by a parent process other than explorer.exe. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process names. This activity is significant because reg.exe is often used in registry manipulation, which can be indicative of malicious behavior such as persistence mechanisms or system configuration changes. If confirmed malicious, this could allow an attacker to modify critical system settings, potentially leading to privilege escalation or persistent access.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Windows Defense Evasion Tactics
- Disabling Security Tools
- DHS Report TA18-074A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_reg_exe_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
