# Windows WMI Impersonate Token

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting potential WMI token impersonation activities in a process or command. It leverages Sysmon EventCode 10 to identify instances where `wmiprvse.exe` has a duplicate handle or full granted access in a target process. This behavior is significant as it is commonly used by malware like Qakbot for privilege escalation or defense evasion. If confirmed malicious, this activity could allow an attacker to gain elevated privileges, evade defenses, and maintain persistence within the environment.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Qakbot
- Water Gamayun

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/wmi_impersonate/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wmi_impersonate_token.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
