# Windows Process Writing File to World Writable Path

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies a process writing a .txt file to a world writable path. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on file creation events within specific directories. This activity is significant as adversaries often use such techniques to deliver payloads to a system, which is uncommon for legitimate processes. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1218.005

## Analytic Stories

- APT29 Diplomatic Deceptions with WINELOADER
- PHP-CGI RCE Attack on Japanese Organizations
- PathWiper

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/mshta_tasks_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_writing_file_to_world_writable_path.yml)*
