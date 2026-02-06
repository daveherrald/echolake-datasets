# Windows Process Injection into Commonly Abused Processes

**Type:** Anomaly

**Author:** 0xC0FFEEEE, Github Community

## Description

The following analytic detects process injection into executables that are commonly abused using Sysmon EventCode 10. It identifies suspicious GrantedAccess requests (0x40 and 0x1fffff) to processes such as notepad.exe, wordpad.exe and calc.exe, excluding common system paths like System32, Syswow64, and Program Files. This behavior is often associated with the SliverC2 framework by BishopFox. Monitoring this activity is crucial as it may indicate an initial payload attempting to execute malicious code. If confirmed malicious, this could allow attackers to execute arbitrary code, potentially leading to privilege escalation or persistent access within the environment.

## MITRE ATT&CK

- T1055.002

## Analytic Stories

- BishopFox Sliver Adversary Emulation Framework
- Earth Alux
- SAP NetWeaver Exploitation
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/sliver/T1055_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_injection_into_commonly_abused_processes.yml)*
