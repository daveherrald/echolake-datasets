# Windows New InProcServer32 Added

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the addition of new InProcServer32 registry keys on Windows endpoints. It leverages data from the Endpoint.Registry datamodel to identify changes in registry paths associated with InProcServer32. This activity is significant because malware often uses this mechanism to achieve persistence or execute malicious code by registering a new InProcServer32 key pointing to a harmful DLL. If confirmed malicious, this could allow an attacker to persist in the environment or execute arbitrary code, posing a significant threat to system integrity and security.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Hellcat Ransomware
- Outlook RCE CVE-2024-21378

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/cve-2024-21378/inprocserver32_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_new_inprocserver32_added.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
