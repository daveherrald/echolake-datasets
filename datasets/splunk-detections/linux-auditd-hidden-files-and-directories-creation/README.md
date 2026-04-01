# Linux Auditd Hidden Files And Directories Creation

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious creation of hidden files and directories, which may indicate an attacker's attempt to conceal malicious activities or unauthorized data. Hidden files and directories are often used to evade detection by security tools and administrators, providing a stealthy means for storing malware, logs, or sensitive information. By monitoring for unusual or unauthorized creation of hidden files and directories, this analytic helps identify potential attempts to hide or unauthorized creation of hidden files and directories, this analytic helps identify potential attempts to hide malicious operations, enabling security teams to uncover and address hidden threats effectively.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1083/linux_auditd_hidden_file/auditd_execve_hidden_file.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_hidden_files_and_directories_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
