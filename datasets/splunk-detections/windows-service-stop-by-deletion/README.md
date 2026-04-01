# Windows Service Stop By Deletion

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of `sc.exe` to delete a Windows service. It leverages Endpoint Detection and Response (EDR) data, focusing on process execution logs that capture command-line arguments. This activity is significant because adversaries often delete services to disable security mechanisms or critical system functions, aiding in evasion and persistence. If confirmed malicious, this action could lead to the termination of essential security services, allowing attackers to operate undetected and potentially escalate their privileges or maintain long-term access to the compromised system.

## MITRE ATT&CK

- T1489

## Analytic Stories

- Azorult
- Graceful Wipe Out Attack
- Crypto Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_stop_by_deletion.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
