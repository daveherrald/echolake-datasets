# Windows Password Managers Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies command-line activity that searches for files related to password manager software, such as "*.kdbx*" and "*credential*". It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. This activity is significant because attackers often target password manager databases to extract stored credentials, which can be used for further exploitation. If confirmed malicious, this behavior could lead to unauthorized access to sensitive information, enabling attackers to escalate privileges, move laterally, or exfiltrate critical data.

## MITRE ATT&CK

- T1555.005

## Analytic Stories

- Windows Post-Exploitation
- Prestige Ransomware
- Scattered Spider
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/winpeas_search_pwd_db/dir-db-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_password_managers_discovery.yml)*
