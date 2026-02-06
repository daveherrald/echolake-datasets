# Windows Njrat Fileless Storage via Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious registry modifications indicative of NjRat's fileless storage technique. It leverages the Endpoint.Registry data model to identify specific registry paths and values commonly used by NjRat for keylogging and executing DLL plugins. This activity is significant as it helps evade traditional file-based detection systems, making it crucial for SOC analysts to monitor. If confirmed malicious, this behavior could allow attackers to persist on the host, execute arbitrary code, and capture sensitive keystrokes, leading to potential data breaches and further system compromise.

## MITRE ATT&CK

- T1027.011

## Analytic Stories

- NjRAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027.011/njrat_fileless_registry_entry/njrat_registry.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_njrat_fileless_storage_via_registry.yml)*
