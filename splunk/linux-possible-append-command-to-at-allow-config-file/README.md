# Linux Possible Append Command To At Allow Config File

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious command lines that append user entries to /etc/at.allow or /etc/at.deny files. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving these files. This activity is significant because altering these configuration files can allow attackers to schedule tasks with elevated permissions, facilitating persistence on a compromised Linux host. If confirmed malicious, this could enable attackers to execute arbitrary code at scheduled intervals, potentially leading to further system compromise and unauthorized access to sensitive information.

## MITRE ATT&CK

- T1053.002

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Scheduled Tasks

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.002/at_execution/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_possible_append_command_to_at_allow_config_file.yml)*
