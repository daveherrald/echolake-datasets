# Windows Disable LogOff Button Through Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting a suspicious registry modification that disables the logoff feature on a Windows host. It leverages data from the Endpoint.Registry data model to identify changes to specific registry values associated with logoff functionality. This activity is significant because it can indicate ransomware attempting to make the compromised host unusable and hinder remediation efforts. If confirmed malicious, this action could prevent users from logging off, complicate incident response, and allow attackers to maintain persistence and control over the affected system.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Ransomware
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/ransomware_disable_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_logoff_button_through_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
