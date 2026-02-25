# Windows Registry Modification for Safe Mode Persistence

**Type:** TTP

**Author:** Teoderick Contreras, Michael Haag, Splunk

## Description

This dataset contains sample data for identifying modifications to the SafeBoot registry keys, specifically within the Minimal and Network paths. This detection leverages registry activity logs from endpoint data sources like Sysmon or EDR tools. Monitoring these keys is crucial as adversaries can use them to persist drivers or services in Safe Mode, with Network allowing network connections. If confirmed malicious, this activity could enable attackers to maintain persistence even in Safe Mode, potentially bypassing certain security measures and facilitating further malicious actions.

## MITRE ATT&CK

- T1547.001

## Analytic Stories

- Ransomware
- Windows Registry Abuse
- Windows Drivers

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_registry_modification_for_safe_mode_persistence.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
