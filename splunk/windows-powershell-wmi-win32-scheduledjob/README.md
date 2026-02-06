# Windows PowerShell WMI Win32 ScheduledJob

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of the Win32_ScheduledJob WMI class via PowerShell script block logging. This class, which manages scheduled tasks, is disabled by default due to security concerns and must be explicitly enabled through registry modifications. The detection leverages PowerShell event code 4104 and script block text analysis. Monitoring this activity is crucial as it may indicate malicious intent, especially if the class was enabled by an attacker. If confirmed malicious, this could allow attackers to persist in the environment by creating scheduled tasks.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Active Directory Lateral Movement

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/win32_scheduledjob_windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_wmi_win32_scheduledjob.yml)*
