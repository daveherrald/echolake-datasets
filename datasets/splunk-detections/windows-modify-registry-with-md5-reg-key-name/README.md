# Windows Modify Registry With MD5 Reg Key Name

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting potentially malicious registry modifications characterized by MD5-like registry key names. It leverages the Endpoint data model to identify registry entries under the SOFTWARE path with 32-character hexadecimal names, a technique often used by NjRAT malware for fileless storage of keylogs and .DLL plugins. This activity is significant as it can indicate the presence of NjRAT or similar malware, which can lead to unauthorized data access and persistent threats within the environment. If confirmed malicious, attackers could maintain persistence and exfiltrate sensitive information.

## MITRE ATT&CK

- T1112

## Analytic Stories

- NjRAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/njrat_md5_registry_entry/njrat_reg_binary.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_with_md5_reg_key_name.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
