# Windows Scheduled Task Service Spawned Shell

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects when the Task Scheduler service ("svchost.exe -k netsvcs -p -s Schedule") spawns common command line, scripting, or shell execution binaries such as "powershell.exe" or "cmd.exe". This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process relationships. This activity is significant as attackers often abuse the Task Scheduler for execution and persistence, blending in with legitimate Windows operations. If confirmed malicious, this could allow attackers to execute arbitrary code, maintain persistence, or escalate privileges within the environment.

## MITRE ATT&CK

- T1053.005
- T1059

## Analytic Stories

- Windows Persistence Techniques

## Data Sources

- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/gootloader/partial_ttps/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_scheduled_task_service_spawned_shell.yml)*
