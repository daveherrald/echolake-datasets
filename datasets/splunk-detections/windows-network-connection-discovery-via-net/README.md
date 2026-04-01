# Windows Network Connection Discovery Via Net

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the execution of `net.exe` with command-line arguments used to list or display information about computer connections. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity can be significant as it indicates potential network reconnaissance by adversaries or Red Teams, aiming to gather situational awareness and Active Directory information. If confirmed malicious, this behavior could allow attackers to map the network, identify critical assets, and plan further attacks, potentially leading to data exfiltration or lateral movement.

## MITRE ATT&CK

- T1049

## Analytic Stories

- Active Directory Discovery
- Azorult
- Windows Post-Exploitation
- Prestige Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1049/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_network_connection_discovery_via_net.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
