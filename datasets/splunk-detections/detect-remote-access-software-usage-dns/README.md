# Detect Remote Access Software Usage DNS

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting DNS queries to domains associated with known remote access software such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer. This detection is crucial as adversaries often use these tools to maintain access and control over compromised environments. Identifying such behavior is vital for a Security Operations Center (SOC) because unauthorized remote access can lead to data breaches, ransomware attacks, and other severe impacts if these threats are not mitigated promptly.

## MITRE ATT&CK

- T1219

## Analytic Stories

- Insider Threat
- Command And Control
- Ransomware
- CISA AA24-241A
- Remote Monitoring and Management Software
- Scattered Spider
- Interlock Ransomware
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1219/screenconnect/screenconnect_sysmon.log


---

*Source: [Splunk Security Content](detections/network/detect_remote_access_software_usage_dns.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
