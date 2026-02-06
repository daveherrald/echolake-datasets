# Linux Composer Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of the Composer tool with elevated privileges on a Linux system. It identifies instances where Composer is run with the 'sudo' command, allowing the user to execute system commands as root. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. This activity is significant because it can indicate an attempt to escalate privileges, potentially leading to unauthorized root access. If confirmed malicious, an attacker could gain full control over the system, execute arbitrary commands, and compromise sensitive data.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/composer/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_composer_privilege_escalation.yml)*
