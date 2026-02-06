# Windows Credentials in Registry Reg Query

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies processes querying the registry for potential passwords or credentials. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that access specific registry paths known to store sensitive information. This activity is significant as it may indicate credential theft attempts, often used by adversaries or post-exploitation tools like winPEAS. If confirmed malicious, this behavior could lead to privilege escalation, persistence, or lateral movement within the network, posing a severe security risk.

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
