# Windows Modify Registry Qakbot Binary Data Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting the creation of a suspicious registry entry by Qakbot malware, characterized by 8 random registry value names with encrypted binary data. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on registry modifications under the "SOFTWARE\\Microsoft\\" path by processes like explorer.exe. This activity is significant as it indicates potential Qakbot infection, which uses the registry to store malicious code or configuration data. If confirmed malicious, this could allow attackers to maintain persistence and execute arbitrary code on the compromised system.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Qakbot

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/qbot2/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_qakbot_binary_data_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
