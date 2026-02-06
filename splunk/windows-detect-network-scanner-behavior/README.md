# Windows Detect Network Scanner Behavior

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic detects when an application is used to connect a large number of unique ports/targets within a short time frame. Network enumeration may be used by adversaries as a method of discovery, lateral movement, or remote execution. This analytic may require significant tuning depending on the organization and applications being actively used, highly recommended to pre-populate the filter macro prior to activation.

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
