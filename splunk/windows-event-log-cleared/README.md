# Windows Event Log Cleared

**Type:** TTP

**Author:** Rico Valdez, Michael Haag, Splunk

## Description

The following analytic detects the clearing of Windows event logs by identifying Windows Security Event ID 1102 or System log event 104. This detection leverages Windows event logs to monitor for log clearing activities. Such behavior is significant as it may indicate an attempt to cover tracks after malicious activities. If confirmed malicious, this action could hinder forensic investigations and allow attackers to persist undetected, making it crucial to investigate further and correlate with other alerts and data sources.

## MITRE ATT&CK

- T1070.001

## Analytic Stories

- ShrinkLocker
- Windows Log Manipulation
- Ransomware
- CISA AA22-264A
- Compromised Windows Host
- Clop Ransomware

## Data Sources

- Windows Event Log Security 1102
- Windows Event Log System 104

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/windows_event_log_cleared/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_event_log_cleared.yml)*
