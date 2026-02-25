# Powershell Remote Thread To Known Windows Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious PowerShell processes attempting to inject code into critical Windows processes using CreateRemoteThread. It leverages Sysmon EventCode 8 to identify instances where PowerShell spawns threads in processes like svchost.exe, csrss.exe, and others. This activity is significant as it is commonly used by malware such as TrickBot and offensive tools like Cobalt Strike to execute malicious payloads, establish reverse shells, or download additional malware. If confirmed malicious, this behavior could lead to unauthorized code execution, privilege escalation, and persistent access within the environment.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Trickbot

## Data Sources

- Sysmon EventID 8

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_remote_thread_to_known_windows_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
