# Linux Sudoers Tmp File Creation

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of the "sudoers.tmp" file, which occurs when editing the /etc/sudoers file using visudo or another editor on a Linux platform. This detection leverages filesystem data to identify the presence of "sudoers.tmp" files. Monitoring this activity is crucial as adversaries may exploit it to gain elevated privileges on a compromised host. If confirmed malicious, this activity could allow attackers to modify sudoers configurations, potentially granting them unauthorized access to execute commands as other users, including root, thereby compromising the system's security.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Persistence Techniques
- China-Nexus Threat Activity
- Salt Typhoon
- Linux Privilege Escalation

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/sudoers_temp/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_sudoers_tmp_file_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
