# Windows Mail Protocol In Non-Common Process Path

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a Windows application establishing an SMTP connection from a non-common installation path. It leverages Sysmon EventCode 3 to identify processes not typically associated with email clients (e.g., Thunderbird, Outlook) making SMTP connections. This activity is significant as adversaries, including malware like AgentTesla, use such connections for Command and Control (C2) communication to exfiltrate stolen data. If confirmed malicious, this behavior could lead to unauthorized data exfiltration, including sensitive information like desktop screenshots, browser data, and system details, compromising the affected host.

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
