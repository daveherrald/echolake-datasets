# Excessive Usage Of SC Service Utility

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting excessive usage of the `sc.exe` service utility on a host machine. It leverages Sysmon EventCode 1 logs to identify instances where `sc.exe` is executed more frequently than normal within a 15-minute window. This behavior is significant as it is commonly associated with ransomware, cryptocurrency miners, and other malware attempting to create, modify, delete, or disable services, potentially related to security applications or for privilege escalation. If confirmed malicious, this activity could allow attackers to manipulate critical services, leading to system compromise or disruption of security defenses.

## MITRE ATT&CK

- T1569.002

## Analytic Stories

- Azorult
- Ransomware
- Crypto Stealer

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/excessive_usage_of_sc_service_utility.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
