# Windows Mail Protocol In Non-Common Process Path

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a Windows application establishing an SMTP connection from a non-common installation path. It leverages Sysmon EventCode 3 to identify processes not typically associated with email clients (e.g., Thunderbird, Outlook) making SMTP connections. This activity is significant as adversaries, including malware like AgentTesla, use such connections for Command and Control (C2) communication to exfiltrate stolen data. If confirmed malicious, this behavior could lead to unauthorized data exfiltration, including sensitive information like desktop screenshots, browser data, and system details, compromising the affected host.

## MITRE ATT&CK

- T1071.003

## Analytic Stories

- AgentTesla

## Data Sources

- Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/agent_tesla/agent_tesla_smtp/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_mail_protocol_in_non_common_process_path.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
