# Linux High Frequency Of File Deletion In Boot Folder

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a high frequency of file deletions in the /boot/ folder on Linux systems. It leverages filesystem event logs to identify when 200 or more files are deleted within an hour by the same process. This behavior is significant as it may indicate the presence of wiper malware, such as Industroyer2, which targets critical system directories. If confirmed malicious, this activity could lead to system instability or failure, hindering the boot process and potentially causing a complete system compromise.

## MITRE ATT&CK

- T1070.004
- T1485

## Analytic Stories

- Data Destruction
- Industroyer2
- AcidPour

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/rm_boot_dir/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_high_frequency_of_file_deletion_in_boot_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
