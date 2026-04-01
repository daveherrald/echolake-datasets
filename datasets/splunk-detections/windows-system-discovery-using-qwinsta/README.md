# Windows System Discovery Using Qwinsta

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of "qwinsta.exe" on a Windows operating system. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. The "qwinsta.exe" tool is significant because it can display detailed session information on a remote desktop session host server. This behavior is noteworthy as it is commonly abused by Qakbot malware to gather system information and send it back to its Command and Control (C2) server. If confirmed malicious, this activity could lead to unauthorized data exfiltration and further compromise of the host.

## MITRE ATT&CK

- T1033

## Analytic Stories

- Qakbot

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/qakbot_discovery_cmdline/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_discovery_using_qwinsta.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
