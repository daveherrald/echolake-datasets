# Detect Regasm with Network Connection

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of regasm.exe establishing a network connection to a public IP address, excluding private IP ranges. This detection leverages Sysmon EventID 3 logs to identify such behavior. This activity is significant as regasm.exe is a legitimate Microsoft-signed binary that can be exploited to bypass application control mechanisms. If confirmed malicious, this behavior could indicate an adversary's attempt to establish a remote Command and Control (C2) channel, potentially leading to privilege escalation and further malicious actions within the environment.

## MITRE ATT&CK

- T1218.009

## Analytic Stories

- Suspicious Regsvcs Regasm Activity
- Living Off The Land
- Handala Wiper
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_regasm_with_network_connection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
