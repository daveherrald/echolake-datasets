# Linux High Frequency Of File Deletion In Etc Folder

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a high frequency of file deletions in the /etc/ folder on Linux systems. It leverages the Endpoint.Filesystem data model to identify instances where 200 or more files are deleted within an hour, grouped by process name and process ID. This behavior is significant as it may indicate the presence of wiper malware, such as AcidRain, which aims to delete critical system files. If confirmed malicious, this activity could lead to severe system instability, data loss, and potential disruption of services.

## MITRE ATT&CK

- T1070.004
- T1485

## Analytic Stories

- AcidRain
- Data Destruction

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/acidrain/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_high_frequency_of_file_deletion_in_etc_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
