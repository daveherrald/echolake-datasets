# Detect HTML Help Spawn Child Process

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of hh.exe (HTML Help) spawning a child process, indicating the use of a Compiled HTML Help (CHM) file to execute Windows script code. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where hh.exe is the parent process. This activity is significant as it may indicate an attempt to execute malicious scripts via CHM files, a known technique for bypassing security controls. If confirmed malicious, this could lead to unauthorized code execution, potentially compromising the system.

## MITRE ATT&CK

- T1218.001

## Analytic Stories

- Suspicious Compiled HTML Activity
- AgentTesla
- Living Off The Land
- Compromised Windows Host
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/application/detect_html_help_spawn_child_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
