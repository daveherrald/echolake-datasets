# Disabling Remote User Account Control

**Type:** TTP

**Author:** David Dorsey, Patrick Bareiss, Splunk

## Description

The following analytic identifies modifications to the registry key that controls the enforcement of Windows User Account Control (UAC). It detects changes to the registry path `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` where the value is set to `0x00000000`. This activity is significant because disabling UAC can allow unauthorized changes to the system without user consent, potentially leading to privilege escalation. If confirmed malicious, an attacker could gain elevated privileges, making it easier to execute further attacks or maintain persistence within the environment.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Windows Defense Evasion Tactics
- Suspicious Windows Registry Activities
- Remcos
- Windows Registry Abuse
- Azorult
- AgentTesla

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disabling_remote_user_account_control.yml)*
