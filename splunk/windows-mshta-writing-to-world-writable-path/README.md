# Windows MSHTA Writing to World Writable Path

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies instances of `mshta.exe` writing files to world-writable directories. It leverages Sysmon EventCode 11 logs to detect file write operations by `mshta.exe` to directories like `C:\Windows\Tasks` and `C:\Windows\Temp`. This activity is significant as it often indicates an attempt to establish persistence or execute malicious code, deviating from the utility's legitimate use. If confirmed malicious, this behavior could lead to the execution of multi-stage payloads, potentially resulting in full system compromise and unauthorized access to sensitive information.

## MITRE ATT&CK

- T1218.005

## Analytic Stories

- APT29 Diplomatic Deceptions with WINELOADER
- Suspicious MSHTA Activity
- XWorm

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/mshta_tasks_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_mshta_writing_to_world_writable_path.yml)*
