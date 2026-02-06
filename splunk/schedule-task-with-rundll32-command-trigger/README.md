# Schedule Task with Rundll32 Command Trigger

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of scheduled tasks in Windows that use the rundll32 command. It leverages Windows Security EventCode 4698, which logs the creation of scheduled tasks, and filters for tasks executed via rundll32. This activity is significant as it is a common technique used by malware, such as TrickBot, to persist in an environment or deliver additional payloads. If confirmed malicious, this could lead to data theft, ransomware deployment, or other damaging outcomes. Immediate investigation and mitigation are crucial to prevent further compromise.

## MITRE ATT&CK

- T1053

## Analytic Stories

- Windows Persistence Techniques
- Living Off The Land
- IcedID
- Scheduled Tasks
- Compromised Windows Host
- Trickbot
- Castle RAT

## Data Sources

- Windows Event Log Security 4698

## Sample Data

- **Source:** WinEventLog:Security
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/tasksched/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/schedule_task_with_rundll32_command_trigger.yml)*
