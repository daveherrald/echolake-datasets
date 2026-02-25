# Linux Possible Cronjob Modification With Editor

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting potential unauthorized modifications to Linux cronjobs using text editors like "nano," "vi," or "vim." It identifies this activity by monitoring command-line executions that interact with cronjob configuration paths. This behavior is significant for a SOC as it may indicate attempts at privilege escalation or establishing persistent access. If confirmed malicious, the impact could be severe, allowing attackers to execute damaging actions such as data theft, system sabotage, or further network penetration.

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

*Source: [Splunk Security Content](detections/endpoint/linux_possible_cronjob_modification_with_editor.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
