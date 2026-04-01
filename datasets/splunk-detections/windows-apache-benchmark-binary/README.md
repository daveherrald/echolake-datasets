# Windows Apache Benchmark Binary

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of the Apache Benchmark binary (ab.exe), commonly used by MetaSploit payloads. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where the original file name is ab.exe. This activity is significant as it may indicate the presence of a MetaSploit attack, which uses Apache Benchmark to generate malicious payloads. If confirmed malicious, this could lead to unauthorized network connections, further system compromise, and potential data exfiltration. Immediate investigation is required to determine the intent and scope of the activity.

## MITRE ATT&CK

- T1059

## Analytic Stories

- MetaSploit

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/metasploit/apachebench_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_apache_benchmark_binary.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
