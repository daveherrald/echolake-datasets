# Windows Detect Network Scanner Behavior

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting when an application is used to connect a large number of unique ports/targets within a short time frame. Network enumeration may be used by adversaries as a method of discovery, lateral movement, or remote execution. This analytic may require significant tuning depending on the organization and applications being actively used, highly recommended to pre-populate the filter macro prior to activation.

## MITRE ATT&CK

- T1595.001
- T1595.002

## Analytic Stories

- Network Discovery
- Windows Discovery Techniques

## Data Sources

- Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1595/sysmon_scanning_events/sysmon_scanning_events.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_detect_network_scanner_behavior.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
