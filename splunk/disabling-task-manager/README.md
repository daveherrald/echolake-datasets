# Disabling Task Manager

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic identifies modifications to the Windows registry that disable Task Manager. It leverages data from the Endpoint.Registry data model, specifically looking for changes to the registry path "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" with a value of "0x00000001". This activity is significant as it is commonly associated with malware such as RATs, Trojans, and worms, which disable Task Manager to prevent users from terminating malicious processes. If confirmed malicious, this could allow attackers to maintain persistence and control over the infected system.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse
- NjRAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disabling_task_manager.yml)*
