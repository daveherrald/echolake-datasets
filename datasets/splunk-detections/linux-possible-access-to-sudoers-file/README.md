# Linux Possible Access To Sudoers File

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting potential access or modification of the /etc/sudoers file on a Linux system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on processes like "cat," "nano," "vim," and "vi" accessing the /etc/sudoers file. This activity is significant because the sudoers file controls user permissions for executing commands with elevated privileges. If confirmed malicious, an attacker could gain persistence or escalate privileges, compromising the security of the targeted host.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Persistence Techniques
- China-Nexus Threat Activity
- Salt Typhoon
- Linux Privilege Escalation

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.008/copy_file_stdoutpipe/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_possible_access_to_sudoers_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
