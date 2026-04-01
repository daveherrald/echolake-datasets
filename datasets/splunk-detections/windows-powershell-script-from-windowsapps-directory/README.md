# Windows PowerShell Script From WindowsApps Directory

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the execution of PowerShell scripts from the WindowsApps directory, which is a common technique used in malicious MSIX package execution. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command lines and parent process paths. This activity is significant as adversaries have been observed using MSIX packages with embedded PowerShell scripts (particularly StartingScriptWrapper.ps1) to execute malicious code. If confirmed malicious, this could allow attackers to execute arbitrary code, establish persistence, or deliver malware while evading traditional detection mechanisms.

## MITRE ATT&CK

- T1059.001
- T1204.002

## Analytic Stories

- MSIX Package Abuse
- Malicious PowerShell

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/msix_powershell/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_script_from_windowsapps_directory.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
