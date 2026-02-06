# Wermgr Process Spawned CMD Or Powershell Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the spawning of cmd or PowerShell processes by the wermgr.exe process. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process telemetry, including parent-child process relationships and command-line executions. This behavior is significant as it is commonly associated with code injection techniques used by malware like TrickBot to execute shellcode or malicious DLL modules. If confirmed malicious, this activity could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment, posing a severe threat to system security.

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
