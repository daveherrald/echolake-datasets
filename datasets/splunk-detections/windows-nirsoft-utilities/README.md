# Windows NirSoft Utilities

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the execution of commonly used NirSoft utilities on Windows systems.
It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution details such as process name, parent process, and command-line arguments.
This activity is significant for a SOC because NirSoft utilities, while legitimate, can be used by adversaries for malicious purposes like credential theft or system reconnaissance.
If confirmed malicious, this activity could lead to unauthorized access, data exfiltration, or further system compromise.
Note that this search does not use a where clause to filter out known benign paths, as NirSoft utilities can be executed from various locations. This might hinder performance in environments with high data volumes.
Apply additional filtering as necessary to enhance this.


## MITRE ATT&CK

- T1588.002

## Analytic Stories

- Data Destruction
- WhisperGate

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1588.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_nirsoft_utilities.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
