# Domain Group Discovery With Wmic

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the execution of `wmic.exe` with command-line arguments used to query for domain groups. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential reconnaissance efforts by adversaries to gain situational awareness and map out Active Directory structures. If confirmed malicious, this behavior could allow attackers to identify and target specific domain groups, potentially leading to privilege escalation or lateral movement within the network.

## MITRE ATT&CK

- T1069.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/domain_group_discovery_with_wmic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
