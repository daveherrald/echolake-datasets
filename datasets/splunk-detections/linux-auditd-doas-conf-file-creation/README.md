# Linux Auditd Doas Conf File Creation

**Type:** TTP

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting the creation of the doas.conf file on a Linux host.
This file is used by the doas utility to allow standard users to perform tasks as root, similar to sudo.
The detection leverages Linux Auditd data, focusing on the creation of the doas.conf file.
This activity is significant because it can indicate an attempt to gain elevated privileges, potentially by an adversary. If confirmed malicious, this could allow an attacker to execute commands with root commands with root privileges, leading to full system compromise.


## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Path
- Linux Auditd Cwd

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/auditd_path_cwd_doas_conf/path_doas.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_doas_conf_file_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
