# Windows Sensitive Group Discovery With Net

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `net.exe` with command-line arguments used to query elevated domain or sensitive groups. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential reconnaissance efforts by adversaries to identify high-privileged users within Active Directory. If confirmed malicious, this behavior could lead to further attacks aimed at compromising privileged accounts, escalating privileges, or gaining unauthorized access to sensitive systems and data.

## MITRE ATT&CK

- T1069.002

## Analytic Stories

- Active Directory Discovery
- Volt Typhoon
- Rhysida Ransomware
- BlackSuit Ransomware
- IcedID
- Microsoft WSUS CVE-2025-59287

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sensitive_group_discovery_with_net.yml)*
