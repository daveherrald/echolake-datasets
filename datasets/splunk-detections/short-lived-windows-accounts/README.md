# Short Lived Windows Accounts

**Type:** TTP

**Author:** David Dorsey, Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting the rapid creation and deletion of Windows accounts within a short time frame of 1 hour. It leverages the "Change" data model in Splunk, specifically monitoring events with result IDs 4720 (account creation) and 4726 (account deletion). This behavior is significant as it may indicate an attacker attempting to create and remove accounts quickly to evade detection or gain unauthorized access. If confirmed malicious, this activity could lead to unauthorized access, privilege escalation, or further malicious actions within the environment. Immediate investigation of flagged events is crucial to mitigate potential damage.

## MITRE ATT&CK

- T1078.003
- T1136.001

## Analytic Stories

- Active Directory Lateral Movement
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Windows Event Log System 4720
- Windows Event Log System 4726

## Sample Data

- **Source:** WinEventLog:Security
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-security.log

- **Source:** WinEventLog:System
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-system.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/short_lived_windows_accounts.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
