# Windows WSUS Spawning Shell

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying instances where a shell (PowerShell.exe or Cmd.exe) is spawned from wsusservice.exe, the Windows Server Update Services process. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where the parent process is wsusservice.exe. This activity is significant as it may indicate exploitation of CVE-2025-59287, a critical deserialization vulnerability in WSUS that allows unauthenticated remote code execution. If confirmed malicious, this behavior could allow attackers to execute arbitrary commands on WSUS servers, potentially leading to system compromise, data exfiltration, domain enumeration, or further lateral movement within the network.

## MITRE ATT&CK

- T1190
- T1505.003

## Analytic Stories

- Microsoft WSUS CVE-2025-59287

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/wsus-windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wsus_spawning_shell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
