# Windows Credentials from Password Stores Query

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the Windows OS tool cmdkey.exe, which is often abused by post-exploitation tools like winpeas, commonly used in ransomware attacks to list stored usernames, passwords, or credentials. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. This activity is significant as it indicates potential credential harvesting, which can lead to privilege escalation and persistence. If confirmed malicious, attackers could gain unauthorized access to sensitive information and maintain control over compromised systems for further exploitation.

## MITRE ATT&CK

- T1555

## Analytic Stories

- Windows Post-Exploitation
- Prestige Ransomware
- DarkGate Malware
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/winpeas_cmdkeylist/cmdkey-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credentials_from_password_stores_query.yml)*
