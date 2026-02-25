# Schtasks scheduling job on remote system

**Type:** TTP

**Author:** David Dorsey, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the use of 'schtasks.exe' to create a scheduled task on a remote system, indicating potential lateral movement or remote code execution. It leverages process data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line arguments and flags. This activity is significant as it may signify an adversary's attempt to persist or execute code remotely. If confirmed malicious, this could allow attackers to maintain access, execute arbitrary commands, or further infiltrate the network, posing a severe security risk.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Scheduled Tasks
- Phemedrone Stealer
- Living Off The Land
- Prestige Ransomware
- Quasar RAT
- RedLine Stealer
- Active Directory Lateral Movement
- NOBELIUM Group
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/schtasks_scheduling_job_on_remote_system.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
