# Sc exe Manipulating Windows Services

**Type:** TTP

**Author:** Rico Valdez, Splunk

## Description

This dataset contains sample data for detecting the creation or modification of Windows services using the sc.exe command. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because manipulating Windows services can be a method for attackers to establish persistence, escalate privileges, or execute arbitrary code. If confirmed malicious, this behavior could allow an attacker to maintain long-term access, disrupt services, or gain control over critical system functions, posing a severe threat to the environment.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- Azorult
- Orangeworm Attack Group
- Windows Drivers
- NOBELIUM Group
- Windows Persistence Techniques
- Disabling Security Tools
- Windows Service Abuse
- DHS Report TA18-074A
- Crypto Stealer
- Scattered Spider

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/sc_exe_manipulating_windows_services.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
