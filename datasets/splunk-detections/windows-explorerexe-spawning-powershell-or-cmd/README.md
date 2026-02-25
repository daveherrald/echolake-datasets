# Windows Explorer.exe Spawning PowerShell or Cmd

**Type:** Hunting

**Author:** Michael Haag, AJ King, Splunk, Jesse Hunter, Splunk Community Contributor

## Description

This detection identifies instances where Windows Explorer.exe spawns PowerShell or cmd.exe processes, particularly focusing on executions initiated by LNK files. This behavior is associated with the ZDI-CAN-25373 Windows shortcut zero-day vulnerability, where specially crafted LNK files are used to trigger malicious code execution through cmd.exe or powershell.exe. This technique has been actively exploited by multiple APT groups in targeted attacks through both HTTP and SMB delivery methods.

## MITRE ATT&CK

- T1059.001
- T1204.002

## Analytic Stories

- ZDI-CAN-25373 Windows Shortcut Exploit Abused as Zero-Day

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/encoded_powershell/explorer_spawns_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_explorer_exe_spawning_powershell_or_cmd.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
