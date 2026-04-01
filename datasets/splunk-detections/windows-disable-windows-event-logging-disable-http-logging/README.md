# Windows Disable Windows Event Logging Disable HTTP Logging

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of AppCmd.exe to disable HTTP logging on IIS servers. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution events where AppCmd.exe is used with specific parameters to alter logging settings. This activity is significant because disabling HTTP logging can help adversaries hide their tracks and avoid detection by removing evidence of their actions. If confirmed malicious, this could allow attackers to operate undetected, making it difficult to trace their activities and respond to the intrusion effectively.

## MITRE ATT&CK

- T1505.004
- T1562.002

## Analytic Stories

- IIS Components
- CISA AA23-347A
- Compromised Windows Host
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.004/disable_http_logging_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_windows_event_logging_disable_http_logging.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
