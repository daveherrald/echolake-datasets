# SLUI RunAs Elevated

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of the Microsoft Software Licensing User Interface Tool (`slui.exe`) with elevated privileges using the `-verb runas` function. This activity is identified through logs from Endpoint Detection and Response (EDR) agents, focusing on specific registry keys and command-line parameters. This behavior is significant as it indicates a potential privilege escalation attempt, which could allow an attacker to gain elevated access and execute malicious actions with higher privileges. If confirmed malicious, this could lead to unauthorized system changes, data exfiltration, or further compromise of the affected endpoint.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- DarkSide Ransomware
- Compromised Windows Host
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/slui/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/slui_runas_elevated.yml)*
