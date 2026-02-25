# Linux Auditd Virtual Disk File And Directory Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious discovery of virtual disk files and directories, which may indicate an attacker's attempt to locate and access virtualized storage environments. Virtual disks can contain sensitive data or critical system configurations, and unauthorized discovery attempts could signify preparatory actions for data exfiltration or further compromise. By monitoring for unusual or unauthorized searches for virtual disk files and directories, this analytic helps identify potential reconnaissance activities, enabling security teams to respond promptly and safeguard against unauthorized access and data breaches.

## MITRE ATT&CK

- T1083

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Execve

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1083/linux_auditd_find_virtual_disk/auditd_execve_find_vhd.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_virtual_disk_file_and_directory_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
