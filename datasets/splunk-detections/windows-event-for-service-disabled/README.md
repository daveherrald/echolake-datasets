# Windows Event For Service Disabled

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting when a Windows service is modified from a start type to disabled. It leverages system event logs, specifically EventCode 7040, to identify this change. This activity is significant because adversaries often disable security or other critical services to evade detection and maintain control over a compromised host. If confirmed malicious, this action could allow attackers to bypass security defenses, leading to further exploitation and persistence within the environment.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- RedLine Stealer

## Data Sources

- Windows Event Log System 7040

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/windows_excessive_disabled_services_event/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_event_for_service_disabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
