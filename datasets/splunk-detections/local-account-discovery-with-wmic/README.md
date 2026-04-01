# Local Account Discovery With Wmic

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of `wmic.exe` with command-line arguments used to query local user accounts, specifically the `useraccount` argument. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant as it indicates potential reconnaissance efforts by adversaries to enumerate local users, which is a common step in situational awareness and Active Directory discovery. If confirmed malicious, this behavior could lead to further targeted attacks, privilege escalation, or lateral movement within the network.

## MITRE ATT&CK

- T1087.001

## Analytic Stories

- Active Directory Discovery
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.001/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/local_account_discovery_with_wmic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
