# Detect Regsvcs Spawning a Process

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying regsvcs.exe spawning a child process. This behavior is detected using Endpoint Detection and Response (EDR) telemetry, focusing on process creation events where the parent process is regsvcs.exe. This activity is significant because regsvcs.exe rarely spawns child processes, and such behavior can indicate an attempt to bypass application control mechanisms. If confirmed malicious, this could allow an attacker to execute arbitrary code, potentially leading to privilege escalation or persistent access within the environment. Immediate investigation is recommended to determine the legitimacy of the spawned process and any associated suspicious activities.

## MITRE ATT&CK

- T1218.009

## Analytic Stories

- Suspicious Regsvcs Regasm Activity
- Living Off The Land
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_regsvcs_spawning_a_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
