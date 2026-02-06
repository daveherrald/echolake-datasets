# Linux MySQL Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of MySQL commands with elevated privileges using sudo, which can lead to privilege escalation. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because it indicates a potential misuse of MySQL to execute system commands as root, which could allow an attacker to gain root shell access. If confirmed malicious, this could result in full control over the affected system, leading to severe security breaches and unauthorized access to sensitive data.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/mysql/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_mysql_privilege_escalation.yml)*
