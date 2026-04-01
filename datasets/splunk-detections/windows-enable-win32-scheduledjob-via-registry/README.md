# Windows Enable Win32 ScheduledJob via Registry

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the creation of a new DWORD value named "EnableAt" in the registry path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration". This modification enables the use of the at.exe or wmi Win32_ScheduledJob commands to add scheduled tasks on a Windows endpoint. The detection leverages registry event data from the Endpoint datamodel. This activity is significant because it may indicate that an attacker is enabling the ability to schedule tasks, potentially to execute malicious code at specific times or intervals. If confirmed malicious, this could allow persistent code execution on the system.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Active Directory Lateral Movement
- Scheduled Tasks

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/enableat_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_enable_win32_scheduledjob_via_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
