# Windows Process Execution in Temp Dir

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying processes running from %temp% directory file paths. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific process paths within the Endpoint data model. This activity is significant because adversaries often use unconventional file paths to execute malicious code without requiring administrative privileges. If confirmed malicious, this behavior could indicate an attempt to bypass security controls, leading to unauthorized software execution, potential system compromise, and further malicious activities within the environment.

## MITRE ATT&CK

- T1543
- T1036.005

## Analytic Stories

- AgentTesla
- XWorm
- NjRAT
- Remcos
- Ryuk Ransomware
- Ransomware
- Qakbot
- Trickbot
- PathWiper
- PromptLock
- Lokibot
- SesameOp

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/process_temp_path/process_temp_path.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_execution_in_temp_dir.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
