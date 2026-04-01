# Detect RClone Command-Line Usage

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the usage of `rclone.exe` with specific command-line arguments indicative of file transfer activities. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process details. This activity is significant as `rclone.exe` is often used by adversaries for data exfiltration, especially during ransomware attacks. If confirmed malicious, this behavior could lead to unauthorized data transfer, resulting in data breaches and potential loss of sensitive information. Immediate isolation of the affected endpoint and further investigation are recommended.

## MITRE ATT&CK

- T1020

## Analytic Stories

- Storm-0501 Ransomware
- Hellcat Ransomware
- DarkSide Ransomware
- Ransomware
- Black Basta Ransomware
- Cactus Ransomware
- Cisco Network Visibility Module Analytics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1020/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_rclone_command_line_usage.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
