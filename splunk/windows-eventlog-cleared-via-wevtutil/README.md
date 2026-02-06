# Windows Eventlog Cleared Via Wevtutil

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the usage of wevtutil.exe with the "clear-log" parameter in order to clear the contents of logs. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because clearing event logs can be an attempt to cover tracks after malicious actions, hindering forensic investigations. If confirmed malicious, this behavior could allow an attacker to erase evidence of their activities, making it difficult to trace their actions and understand the full scope of the compromise.


## MITRE ATT&CK

- T1070.001

## Analytic Stories

- Windows Log Manipulation
- Ransomware
- Rhysida Ransomware
- Clop Ransomware
- CISA AA23-347A
- ShrinkLocker

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/windows_pwh_log_cleared/wevtutil_clear_log.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_eventlog_cleared_via_wevtutil.yml)*
