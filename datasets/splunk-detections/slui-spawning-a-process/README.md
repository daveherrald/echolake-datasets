# SLUI Spawning a Process

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the Microsoft Software Licensing User Interface Tool (`slui.exe`) spawning a child process. This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on process creation events where `slui.exe` is the parent process. This activity is significant because `slui.exe` should not typically spawn child processes, and doing so may indicate a UAC bypass attempt, leading to elevated privileges. If confirmed malicious, an attacker could leverage this to execute code with elevated privileges, potentially compromising the system's security and gaining unauthorized access.

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

*Source: [Splunk Security Content](detections/endpoint/slui_spawning_a_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
