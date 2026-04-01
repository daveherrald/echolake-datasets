# Linux File Creation In Init Boot Directory

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of files in Linux init boot directories, which are used for automatic execution upon system startup. It leverages file system logs to identify new files in directories such as /etc/init.d/ and /etc/rc.d/. This activity is significant as it is a common persistence technique used by adversaries, malware authors, and red teamers. If confirmed malicious, this could allow an attacker to maintain persistence on the compromised host, potentially leading to further exploitation and unauthorized control over the system.

## MITRE ATT&CK

- T1037.004

## Analytic Stories

- China-Nexus Threat Activity
- Backdoor Pingpong
- Linux Persistence Techniques
- XorDDos
- Linux Privilege Escalation

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.004/linux_init_profile/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_file_creation_in_init_boot_directory.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
