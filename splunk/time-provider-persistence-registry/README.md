# Time Provider Persistence Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects suspicious modifications to the time provider registry for persistence and autostart. It leverages data from the Endpoint.Registry data model, focusing on changes to the "CurrentControlSet\\Services\\W32Time\\TimeProviders" registry path. This activity is significant because such modifications are uncommon and can indicate an attempt to establish persistence on a compromised host. If confirmed malicious, this technique allows an attacker to maintain access and execute code automatically upon system boot, potentially leading to further exploitation and control over the affected system.

## MITRE ATT&CK

- T1547.003

## Analytic Stories

- Hermetic Wiper
- Windows Privilege Escalation
- Windows Persistence Techniques
- Windows Registry Abuse
- Data Destruction

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.003/timeprovider_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/time_provider_persistence_registry.yml)*
