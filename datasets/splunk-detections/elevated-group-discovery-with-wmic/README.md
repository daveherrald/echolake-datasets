# Elevated Group Discovery With Wmic

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of `wmic.exe` with command-line arguments querying specific elevated domain groups. It leverages Endpoint Detection and Response (EDR) telemetry to identify processes that access the LDAP namespace and search for groups like "Domain Admins" or "Enterprise Admins." This activity is significant as it indicates potential reconnaissance efforts by adversaries to identify high-privilege accounts within Active Directory. If confirmed malicious, this behavior could lead to privilege escalation, allowing attackers to gain elevated access and control over critical network resources.

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

*Source: [Splunk Security Content](detections/endpoint/elevated_group_discovery_with_wmic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
