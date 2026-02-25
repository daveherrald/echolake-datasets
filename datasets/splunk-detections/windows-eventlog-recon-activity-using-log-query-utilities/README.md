# Windows EventLog Recon Activity Using Log Query Utilities

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects EventLog reconnaissance activity using utilities such as `wevtutil.exe`, `wmic.exe`, PowerShell cmdlets like `Get-WinEvent`, or WMI queries targeting `Win32_NTLogEvent`. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. These tools are often used by adversaries to extract usernames, IP addresses, session data, and event information for credential access or situational awareness during lateral movement. While these utilities are legitimate, execution with specific arguments or targeting sensitive logs like `Security`, `PowerShell`, or specific EventIDs (e.g., 4624, 4778) can indicate malicious intent. If confirmed malicious, this behavior could allow an attacker to extract sensitive info and potentially have leveraged access or move laterally.


## MITRE ATT&CK

- T1654

## Analytic Stories

- Windows Discovery Techniques

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1654/eventlog_enumeration/eventlog_enumeration.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_eventlog_recon_activity_using_log_query_utilities.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
