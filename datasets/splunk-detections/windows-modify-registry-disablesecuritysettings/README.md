# Windows Modify Registry DisableSecuritySettings

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry that disable security settings for Terminal Services. It leverages the Endpoint data model, specifically monitoring changes to the registry path associated with Terminal Services security settings. This activity is significant because altering these settings can weaken the security posture of Remote Desktop Services, potentially allowing unauthorized remote access. If confirmed malicious, such modifications could enable attackers to gain persistent remote access to the system, facilitating further exploitation and data exfiltration.

## MITRE ATT&CK

- T1112

## Analytic Stories

- DarkGate Malware
- CISA AA23-347A

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/disablesecuritysetting.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_disablesecuritysettings.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
