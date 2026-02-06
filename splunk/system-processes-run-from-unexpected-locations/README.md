# System Processes Run From Unexpected Locations

**Type:** Anomaly

**Author:** David Dorsey, Michael Haag, Nasreddine Bencherchali, Splunk

## Description

The following analytic identifies system processes running from unexpected locations outside of paths such as `C:\Windows\System32\` or `C:\Windows\SysWOW64`. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process paths, names, and hashes. This activity is significant as it may indicate a malicious process attempting to masquerade as a legitimate system process. If confirmed malicious, this behavior could allow an attacker to execute code, escalate privileges, or maintain persistence within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1036.003

## Analytic Stories

- Suspicious Command-Line Executions
- Unusual Processes
- Ransomware
- Masquerading - Rename System Utilities
- Qakbot
- Windows Error Reporting Service Elevation of Privilege Vulnerability
- DarkGate Malware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/system_processes_run_from_unexpected_locations.yml)*
