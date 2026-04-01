# Windows File and Directory Permissions Remove Inheritance

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the removal of permission inheritance using ICACLS. This analytic identifies instances where ICACLS is used to remove permission inheritance from files or directories. The /inheritance:r flag, which strips inherited permissions while optionally preserving or altering explicit permissions, is monitored to detect changes that may restrict access or establish isolated permission configurations. Removing inheritance can be a legitimate administrative action but may also indicate an attempt to conceal malicious activity or bypass inherited security controls.

## MITRE ATT&CK

- T1222.001

## Analytic Stories

- Crypto Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/icacls_inheritance/icacls_process_1.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_file_and_directory_permissions_remove_inheritance.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
