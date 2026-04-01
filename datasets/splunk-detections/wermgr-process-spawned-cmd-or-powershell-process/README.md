# Wermgr Process Spawned CMD Or Powershell Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the spawning of cmd or PowerShell processes by the wermgr.exe process. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process telemetry, including parent-child process relationships and command-line executions. This behavior is significant as it is commonly associated with code injection techniques used by malware like TrickBot to execute shellcode or malicious DLL modules. If confirmed malicious, this activity could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment, posing a severe threat to system security.

## MITRE ATT&CK

- T1059

## Analytic Stories

- Trickbot
- Qakbot

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/wermgr_process_spawned_cmd_or_powershell_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
