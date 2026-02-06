# Windows Unusual SysWOW64 Process Run System32 Executable

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects an unusual process execution pattern where a process running from C:\Windows\SysWOW64\ attempts to execute a binary from C:\Windows\System32\. In a typical Windows environment, 32-bit processes under SysWOW64 should primarily interact with 32-bit binaries within the same directory. However, an execution flow where a 32-bit process spawns a 64-bit binary from System32 can indicate potential process injection, privilege escalation, evasion techniques, or unauthorized execution hijacking.

## MITRE ATT&CK

- T1036.009

## Analytic Stories

- DarkGate Malware
- Salt Typhoon
- China-Nexus Threat Activity

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.009/32bit_process_execute_64bit/32bit_spawn_64bit.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_syswow64_process_run_system32_executable.yml)*
