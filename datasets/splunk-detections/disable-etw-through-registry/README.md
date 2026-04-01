# Disable ETW Through Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting modifications to the registry that disable the Event Tracing for Windows (ETW) feature. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path "*\\SOFTWARE\\Microsoft\\.NETFramework\\ETWEnabled" with a value set to "0x00000000". This activity is significant because disabling ETW can allow attackers to evade detection mechanisms, making it harder for security tools to monitor malicious activities. If confirmed malicious, this could enable attackers to execute payloads with minimal alerts, impairing defenses and potentially leading to further compromise of the system.

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

*Source: [Splunk Security Content](detections/endpoint/disable_etw_through_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
