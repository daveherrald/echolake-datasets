# Domain Account Discovery with Wmic

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of `wmic.exe` with command-line arguments used to query for domain users. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line patterns indicative of domain account discovery. This activity is significant as it often precedes lateral movement or privilege escalation attempts by adversaries. If confirmed malicious, this behavior could allow attackers to map out user accounts within the domain, facilitating further attacks and potentially compromising sensitive information.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery
- Interlock Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/domain_account_discovery_with_wmic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
