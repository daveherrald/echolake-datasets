# Linux Auditd Possible Access To Credential Files

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting attempts to access or dump the contents of /etc/passwd and /etc/shadow files on Linux systems. It leverages data from Linux Auditd, focusing on processes like 'cat', 'nano', 'vim', and 'vi' accessing these files. This activity is significant as it may indicate credential dumping, a technique used by adversaries to gain persistence or escalate privileges. If confirmed malicious, privileges. If confirmed malicious, attackers could obtain hashed passwords for offline cracking, leading to unauthorized access and potential system compromise.

## MITRE ATT&CK

- T1003.008

## Analytic Stories

- Linux Persistence Techniques
- Compromised Linux Host
- China-Nexus Threat Activity
- Salt Typhoon
- Linux Privilege Escalation

## Data Sources

- Linux Auditd Proctitle

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.008/linux_auditd_access_credential/auditd_proctitle_access_cred.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_possible_access_to_credential_files.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
