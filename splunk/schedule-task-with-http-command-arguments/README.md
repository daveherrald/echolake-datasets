# Schedule Task with HTTP Command Arguments

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of scheduled tasks on Windows systems that include HTTP command arguments, using Windows Security EventCode 4698. It identifies tasks registered via schtasks.exe or TaskService with HTTP in their command arguments. This behavior is significant as it often indicates malware activity or the use of Living off the Land binaries (lolbins) to download additional payloads. If confirmed malicious, this activity could lead to data exfiltration, malware propagation, or unauthorized access to sensitive information, necessitating immediate investigation and mitigation.

## MITRE ATT&CK

- T1053

## Analytic Stories

- Windows Persistence Techniques
- Living Off The Land
- Compromised Windows Host
- Scheduled Tasks
- Winter Vivern
- Hellcat Ransomware

## Data Sources

- Windows Event Log Security 4698

## Sample Data

- **Source:** WinEventLog:Security
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/tasksched/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/schedule_task_with_http_command_arguments.yml)*
