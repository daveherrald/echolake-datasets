# Detect Regsvcs with Network Connection

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying instances of Regsvcs.exe establishing a network connection to a public IP address, excluding private IP ranges. This detection leverages Sysmon EventID 3 logs to monitor network connections initiated by Regsvcs.exe. This activity is significant as Regsvcs.exe, a legitimate Microsoft-signed binary, can be exploited to bypass application control mechanisms and establish remote Command and Control (C2) channels. If confirmed malicious, this behavior could allow an attacker to escalate privileges, persist in the environment, and exfiltrate sensitive data. Immediate investigation and remediation are recommended.

## MITRE ATT&CK

- T1218.009

## Analytic Stories

- Suspicious Regsvcs Regasm Activity
- Living Off The Land
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_regsvcs_with_network_connection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
