# System User Discovery With Query

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of `query.exe` with command-line arguments aimed at discovering logged-in users. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as adversaries may use `query.exe` to gain situational awareness and perform Active Directory discovery on compromised endpoints. If confirmed malicious, this behavior could allow attackers to identify active users, aiding in further lateral movement and privilege escalation within the network.

## MITRE ATT&CK

- T1033

## Analytic Stories

- Active Directory Discovery
- Medusa Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/system_user_discovery_with_query.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
