# Windows Process Injection Wermgr Child Process

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying a suspicious instance of wermgr.exe spawning a child process unrelated to error or fault handling. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process relationships and command-line executions. This activity is significant as it can indicate Qakbot malware, which injects malicious code into wermgr.exe to evade detection and execute malicious actions. If confirmed malicious, this behavior could allow an attacker to conduct reconnaissance, execute arbitrary code, and persist within the network, posing a severe security risk.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Qakbot
- Windows Error Reporting Service Elevation of Privilege Vulnerability

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/qbot_wermgr/sysmon_wermgr.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_injection_wermgr_child_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
