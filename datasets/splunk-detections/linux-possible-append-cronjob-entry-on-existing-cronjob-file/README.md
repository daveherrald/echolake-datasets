# Linux Possible Append Cronjob Entry on Existing Cronjob File

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting potential tampering with cronjob files on a Linux system by identifying 'echo' commands that append code to existing cronjob files. It leverages logs from Endpoint Detection and Response (EDR) agents, focusing on process names, parent processes, and command-line executions. This activity is significant because adversaries often use it for persistence or privilege escalation. If confirmed malicious, this could allow attackers to execute unauthorized code automatically, leading to system compromises and unauthorized data access, thereby impacting business operations and data integrity.

## MITRE ATT&CK

- T1053.003

## Analytic Stories

- XorDDos
- Linux Living Off The Land
- Linux Privilege Escalation
- Scheduled Tasks
- Linux Persistence Techniques

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.003/cronjobs_entry/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_possible_append_cronjob_entry_on_existing_cronjob_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
