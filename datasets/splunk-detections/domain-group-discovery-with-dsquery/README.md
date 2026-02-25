# Domain Group Discovery With Dsquery

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the execution of `dsquery.exe` with command-line arguments used to query for domain groups. It leverages Endpoint Detection and Response (EDR) data, focusing on process names and command-line arguments. This activity is significant because both Red Teams and adversaries use `dsquery.exe` to enumerate domain groups, gaining situational awareness and facilitating further Active Directory discovery. If confirmed malicious, this behavior could allow attackers to map out the domain structure, identify high-value targets, and plan subsequent attacks, potentially leading to privilege escalation or data exfiltration.

## MITRE ATT&CK

- T1069.002

## Analytic Stories

- Active Directory Discovery
- LAMEHUG

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/domain_group_discovery_with_dsquery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
