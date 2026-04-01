# Linux Auditd Database File And Directory Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious database file and directory discovery activities, which may signal an attacker attempt to locate and assess critical database assets on a compromised system. This behavior is often a precursor to data theft, unauthorized access, or privilege escalation, as attackers seek to identify valuable information stored in databases. By monitoring for unusual or unauthorized attempts to locate database files and directories, this analytic aids in early detection of potential reconnaissance or data breach efforts, enabling security teams to respond swiftly and mitigate the risk of further compromise.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1083/linux_auditd_find_db/linux_auditd_find_db.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_database_file_and_directory_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
