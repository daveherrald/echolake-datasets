# Windows System Network Connections Discovery Netsh

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the Windows built-in tool netsh.exe to display the state, configuration, and profile of the host firewall. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process metadata. Monitoring this activity is crucial as netsh.exe can be used by adversaries to bypass firewall rules or discover firewall settings. If confirmed malicious, this activity could allow attackers to manipulate firewall configurations, potentially leading to unauthorized network access or data exfiltration.

## MITRE ATT&CK

- T1049

## Analytic Stories

- Windows Post-Exploitation
- Prestige Ransomware
- Snake Keylogger

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_network_connections_discovery_netsh.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
