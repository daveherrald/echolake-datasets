# Windows PowerShell ScheduleTask

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects potential malicious activities involving PowerShell's task scheduling cmdlets. It leverages PowerShell Script Block Logging (EventCode 4104) to identify unusual or suspicious use of cmdlets like 'New-ScheduledTask' and 'Set-ScheduledTask'. This activity is significant as attackers often use these cmdlets for persistence and remote execution of malicious code. If confirmed malicious, this could allow attackers to maintain access, deliver additional payloads, or execute ransomware, leading to data theft or other severe impacts. Immediate investigation and mitigation are crucial to prevent further compromise.

## MITRE ATT&CK

- T1053.005
- T1059.001

## Analytic Stories

- Scheduled Tasks
- Scattered Spider

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/atomic_red_team/pwsh_scheduledtask.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_scheduletask.yml)*
