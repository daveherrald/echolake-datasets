# Windows Deleted Registry By A Non Critical Process File Path

**Type:** Anomaly

**Author:** Steven Dick, Teoderick Contreras, Splunk

## Description

The following analytic detects the deletion of registry keys by non-critical processes. It leverages Endpoint Detection and Response (EDR) data, focusing on registry deletion events and correlating them with processes not typically associated with system or program files. This activity is significant as it may indicate malware, such as the Double Zero wiper, attempting to evade defenses or cause destructive payload impacts. If confirmed malicious, this behavior could lead to significant system damage, loss of critical configurations, and potential disruption of services.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Data Destruction
- Double Zero Destructor

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 12

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/doublezero_wiper/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_deleted_registry_by_a_non_critical_process_file_path.yml)*
