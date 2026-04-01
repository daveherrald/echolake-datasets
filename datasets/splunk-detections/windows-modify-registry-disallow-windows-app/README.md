# Windows Modify Registry DisAllow Windows App

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry aimed at preventing the execution of specific computer programs. It leverages data from the Endpoint.Registry datamodel, focusing on changes to the registry path "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun*" with a value of "0x00000001". This activity is significant as it can indicate an attempt to disable security tools, a tactic used by malware like Azorult. If confirmed malicious, this could allow an attacker to evade detection and maintain persistence on the compromised host.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Azorult

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_disallow_windows_app.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
