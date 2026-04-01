# Linux Auditd Possible Access To Sudoers File

**Type:** Anomaly

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting potential access or modification of the /etc/sudoers file on a Linux system.
It leverages data from Linux Auditd, focusing on events of type PATH or CWD.
This activity could be significant because the sudoers file controls user permissions for executing commands with elevated privileges.
Correlate this with related EXECVE or PROCTITLE events to identify the process or user responsible for the access or modification.
If confirmed malicious, an attacker could gain persistence or escalate privileges, compromising the security of the targeted host.


## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Persistence Techniques
- Compromised Linux Host
- China-Nexus Threat Activity
- Salt Typhoon
- Linux Privilege Escalation

## Data Sources

- Linux Auditd Path
- Linux Auditd Cwd

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/auditd_path_sudoers/path_sudoers.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_possible_access_to_sudoers_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
