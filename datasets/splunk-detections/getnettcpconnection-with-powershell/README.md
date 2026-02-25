# GetNetTcpconnection with PowerShell

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the execution of `powershell.exe` with the `Get-NetTcpConnection` command, which lists current TCP connections on a system. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. Monitoring this activity is significant as it may indicate an adversary or Red Team performing network reconnaissance or situational awareness. If confirmed malicious, this activity could allow attackers to map network connections, aiding in lateral movement or further exploitation within the network.

## MITRE ATT&CK

- T1049

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1049/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/getnettcpconnection_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
