# Windows Cached Domain Credentials Reg Query

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies a process command line querying the CachedLogonsCount registry value in the Winlogon registry. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and registry queries. Monitoring this activity is significant as it can indicate the use of post-exploitation tools like Winpeas, which gather information about login caching settings. If confirmed malicious, this activity could help attackers understand login caching configurations, potentially aiding in credential theft or lateral movement within the network.

## MITRE ATT&CK

- T1003.005

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_cached_domain_credentials_reg_query.yml)*
