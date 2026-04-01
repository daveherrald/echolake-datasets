# Suspicious wevtutil Usage

**Type:** TTP

**Author:** David Dorsey, Michael Haag, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the usage of wevtutil.exe with parameters for clearing event logs such as Application, Security, Setup, Trace, or System. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because clearing event logs can be an attempt to cover tracks after malicious actions, hindering forensic investigations. If confirmed malicious, this behavior could allow an attacker to erase evidence of their activities, making it difficult to trace their actions and understand the full scope of the compromise.

## MITRE ATT&CK

- T1070.001

## Analytic Stories

- Windows Log Manipulation
- Ransomware
- Rhysida Ransomware
- Clop Ransomware
- CISA AA23-347A
- ShrinkLocker
- Storm-2460 CLFS Zero Day Exploitation
- Scattered Spider
- Storm-0501 Ransomware
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/windows_pwh_log_cleared/wevtutil_clear_log.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_wevtutil_usage.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
