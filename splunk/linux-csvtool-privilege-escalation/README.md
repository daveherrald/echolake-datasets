# Linux Csvtool Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of the 'csvtool' command with 'sudo' privileges, which can allow a user to run system commands as root. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because it indicates a potential privilege escalation attempt, where a user could gain unauthorized root access. If confirmed malicious, this could lead to full system compromise, allowing an attacker to execute arbitrary commands, escalate privileges, and maintain persistent access.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Living Off The Land

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/csvtool/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_csvtool_privilege_escalation.yml)*
