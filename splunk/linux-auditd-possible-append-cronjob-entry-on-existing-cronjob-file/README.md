# Linux Auditd Possible Append Cronjob Entry On Existing Cronjob File

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects potential tampering with cronjob files on a Linux system.
It leverages logs from Linux Auditd, focusing on events of type PATH or CWD.
This activity could be significant because adversaries often use it for persistence or privilege escalation.
Correlate this with related EXECVE or PROCTITLE events to identify the process or user responsible for the access or modification.
If confirmed malicious, this could allow attackers to execute unauthorized code automatically, leading to system compromises and unauthorized data access, thereby impacting business operations and data integrity.


## MITRE ATT&CK

- T1053.003

## Analytic Stories

- XorDDos
- Linux Living Off The Land
- Compromised Linux Host
- Linux Privilege Escalation
- Scheduled Tasks
- Linux Persistence Techniques

## Data Sources

- Linux Auditd Path
- Linux Auditd Cwd

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.003/auditd_path_cron/path_cron.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_possible_append_cronjob_entry_on_existing_cronjob_file.yml)*
