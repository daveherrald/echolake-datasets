# Linux Add Files In Known Crontab Directories

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects unauthorized file creation in known crontab directories on Unix-based systems. It leverages filesystem data to identify new files in directories such as /etc/cron* and /var/spool/cron/*. This activity is significant as it may indicate an attempt by threat actors or malware to establish persistence on a compromised host. If confirmed malicious, this could allow attackers to execute arbitrary code at scheduled intervals, potentially leading to further system compromise and unauthorized access to sensitive information.

## MITRE ATT&CK

- T1053.003

## Analytic Stories

- XorDDos
- Linux Living Off The Land
- Linux Privilege Escalation
- Scheduled Tasks
- Linux Persistence Techniques

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.003/cronjobs_entry/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_add_files_in_known_crontab_directories.yml)*
