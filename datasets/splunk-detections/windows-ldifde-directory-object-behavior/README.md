# Windows Ldifde Directory Object Behavior

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the use of Ldifde.exe, a command-line utility for creating, modifying, or deleting LDAP directory objects. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution and command-line arguments. Monitoring Ldifde.exe is significant because it can be used by attackers to manipulate directory objects, potentially leading to unauthorized changes or data exfiltration. If confirmed malicious, this activity could allow an attacker to gain control over directory services, escalate privileges, or access sensitive information within the network.

## MITRE ATT&CK

- T1105
- T1069.002

## Analytic Stories

- Volt Typhoon

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/ldifde_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ldifde_directory_object_behavior.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
