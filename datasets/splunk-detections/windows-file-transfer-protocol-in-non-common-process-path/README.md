# Windows File Transfer Protocol In Non-Common Process Path

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting FTP connections initiated by processes located in non-standard installation paths on Windows systems. It leverages Sysmon EventCode 3 to identify network connections where the process image path does not match common directories like "Program Files" or "Windows\System32". This activity is significant as FTP is often used by adversaries and malware, such as AgentTesla, for Command and Control (C2) communications to exfiltrate stolen data. If confirmed malicious, this could lead to unauthorized data transfer, exposing sensitive information and compromising the integrity of the affected host.

## MITRE ATT&CK

- T1071.003

## Analytic Stories

- AgentTesla
- Snake Keylogger
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/agent_tesla/agent_tesla_ftp/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_file_transfer_protocol_in_non_common_process_path.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
