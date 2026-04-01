# Disable AMSI Through Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting modifications to the Windows registry that disable the Antimalware Scan Interface (AMSI) by setting the "AmsiEnable" value to "0x00000000". This detection leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path "*\\SOFTWARE\\Microsoft\\Windows Script\\Settings\\AmsiEnable". Disabling AMSI is significant as it is a common technique used by ransomware, Remote Access Trojans (RATs), and Advanced Persistent Threats (APTs) to evade detection and impair defenses. If confirmed malicious, this activity could allow attackers to execute payloads with minimal alerts, leading to potential system compromise and data exfiltration.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Ransomware
- CISA AA23-347A
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_amsi_through_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
