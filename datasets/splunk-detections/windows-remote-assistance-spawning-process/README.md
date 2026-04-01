# Windows Remote Assistance Spawning Process

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting Microsoft Remote Assistance (msra.exe) spawning PowerShell.exe or cmd.exe as a child process. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where msra.exe is the parent process. This activity is significant because msra.exe typically does not spawn command-line interfaces, indicating potential process injection or misuse. If confirmed malicious, an attacker could use this technique to execute arbitrary commands, escalate privileges, or maintain persistence on the compromised system.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Unusual Processes
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/msra/msra-windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_remote_assistance_spawning_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
