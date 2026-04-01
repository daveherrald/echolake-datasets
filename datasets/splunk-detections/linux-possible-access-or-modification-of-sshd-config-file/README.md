# Linux Possible Access Or Modification Of sshd Config File

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious access or modification of the sshd_config file on Linux systems. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving processes like "cat," "nano," "vim," and "vi" accessing the sshd_config file. This activity is significant because unauthorized changes to sshd_config can allow threat actors to redirect port connections or use unauthorized keys, potentially compromising the system. If confirmed malicious, this could lead to unauthorized access, privilege escalation, or persistent backdoor access, posing a severe security risk.

## MITRE ATT&CK

- T1098.004

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Living Off The Land

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.004/ssh_authorized_keys/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_possible_access_or_modification_of_sshd_config_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
