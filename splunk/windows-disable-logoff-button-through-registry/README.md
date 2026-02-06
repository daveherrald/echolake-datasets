# Windows Disable LogOff Button Through Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects a suspicious registry modification that disables the logoff feature on a Windows host. It leverages data from the Endpoint.Registry data model to identify changes to specific registry values associated with logoff functionality. This activity is significant because it can indicate ransomware attempting to make the compromised host unusable and hinder remediation efforts. If confirmed malicious, this action could prevent users from logging off, complicate incident response, and allow attackers to maintain persistence and control over the affected system.

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
