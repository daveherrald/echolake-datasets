# Windows Credentials in Registry Reg Query

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying processes querying the registry for potential passwords or credentials. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that access specific registry paths known to store sensitive information. This activity is significant as it may indicate credential theft attempts, often used by adversaries or post-exploitation tools like winPEAS. If confirmed malicious, this behavior could lead to privilege escalation, persistence, or lateral movement within the network, posing a severe security risk.

## MITRE ATT&CK

- T1552.002

## Analytic Stories

- Windows Post-Exploitation
- Prestige Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/winpeas_search_pwd/query-putty-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credentials_in_registry_reg_query.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
