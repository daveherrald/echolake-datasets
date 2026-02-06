# Linux Adding Crontab Using List Parameter

**Type:** Hunting

**Author:** Teoderick Contreras, Bhavin Patel, Splunk

## Description

The following analytic detects suspicious modifications to cron jobs on Linux systems using the crontab command with list parameters. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it may indicate an attempt to establish persistence or execute malicious code on a schedule. If confirmed malicious, the impact could include unauthorized code execution, data destruction, or other damaging outcomes. Further investigation should analyze the added cron job, its associated command, and any related processes.

## MITRE ATT&CK

- T1053.003

## Analytic Stories

- Cisco Isovalent Suspicious Activity
- Industroyer2
- Linux Privilege Escalation
- Linux Living Off The Land
- Data Destruction
- Linux Persistence Techniques
- Scheduled Tasks
- Gomir
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.003/crontab_list_parameter/sysmon_linux.log

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_adding_crontab_using_list_parameter.yml)*
