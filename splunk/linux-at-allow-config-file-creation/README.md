# Linux At Allow Config File Creation

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of the /etc/at.allow or /etc/at.deny configuration files in Linux. It leverages file creation events from the Endpoint datamodel to identify when these files are created. This activity is significant as these files control user permissions for the "at" scheduling application and can be abused by attackers to establish persistence. If confirmed malicious, this could allow unauthorized execution of malicious code, leading to potential data theft or further system compromise. Analysts should review the file path, creation time, and associated processes to assess the threat.

## MITRE ATT&CK

- T1053.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Living Off The Land
- Scheduled Tasks

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.002/at_execution/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_at_allow_config_file_creation.yml)*
