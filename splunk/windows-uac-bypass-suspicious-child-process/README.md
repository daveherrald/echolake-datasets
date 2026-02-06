# Windows UAC Bypass Suspicious Child Process

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects when an executable known for User Account Control (UAC) bypass exploitation spawns a child process in a user-controlled location or a command shell executable (e.g., cmd.exe, powershell.exe). This detection leverages Sysmon EventID 1 data, focusing on high or system integrity level processes with specific parent-child process relationships. This activity is significant as it may indicate an attacker has successfully used a UAC bypass exploit to escalate privileges. If confirmed malicious, this could allow the attacker to execute arbitrary commands with elevated privileges, potentially compromising the entire system.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Windows Defense Evasion Tactics
- Living Off The Land
- Castle RAT

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/uac_behavior/uac_behavior_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_uac_bypass_suspicious_child_process.yml)*
