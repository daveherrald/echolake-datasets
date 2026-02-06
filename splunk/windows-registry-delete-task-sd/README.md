# Windows Registry Delete Task SD

**Type:** Anomaly

**Author:** Michael Haag, Teoderick Contreras, Splunk

## Description

The following analytic detects a process attempting to delete a scheduled task's Security Descriptor (SD) from the registry path of that task. It leverages the Endpoint.Registry data model to identify registry actions performed by the SYSTEM user, specifically targeting deletions or modifications of the SD value. This activity is significant as it may indicate an attempt to remove evidence of a scheduled task for defense evasion. If confirmed malicious, it suggests an attacker with privileged access trying to hide their tracks, potentially compromising system integrity and security. Immediate investigation is required.

## MITRE ATT&CK

- T1053.005
- T1562

## Analytic Stories

- Windows Registry Abuse
- Windows Persistence Techniques
- Scheduled Tasks

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/taskschedule/sd_delete_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_registry_delete_task_sd.yml)*
