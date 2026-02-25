# Windows Mshta Execution In Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of mshta.exe via registry entries to run malicious scripts. It leverages registry activity logs to identify entries containing "mshta," "javascript," "vbscript," or "WScript.Shell." This behavior is significant as it indicates potential fileless malware, such as Kovter, which uses encoded scripts in the registry to persist and execute without files. If confirmed malicious, this activity could allow attackers to maintain persistence, execute arbitrary code, and evade traditional file-based detection methods, posing a significant threat to system integrity and security.

## MITRE ATT&CK

- T1218.005

## Analytic Stories

- Suspicious Windows Registry Activities
- Windows Persistence Techniques

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/mshta_in_registry/sysmon3.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_mshta_execution_in_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
