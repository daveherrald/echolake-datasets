# Linux File Creation In Profile Directory

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of files in the /etc/profile.d directory on Linux systems. It leverages filesystem data to identify new files in this directory, which is often used by adversaries for persistence by executing scripts upon system boot. This activity is significant as it may indicate an attempt to maintain long-term access to the compromised host. If confirmed malicious, this could allow attackers to execute arbitrary code with elevated privileges each time the system boots, potentially leading to further compromise and data exfiltration.

## MITRE ATT&CK

- T1546.004

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.004/linux_init_profile/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_file_creation_in_profile_directory.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
