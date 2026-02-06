# Linux Cpulimit Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the use of the 'cpulimit' command with specific flags ('-l', '-f') executed with 'sudo' privileges. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command-line arguments and execution details. This activity is significant because if 'cpulimit' is granted sudo rights, a user can potentially execute system commands as root, leading to privilege escalation. If confirmed malicious, this could allow an attacker to gain root access, execute arbitrary commands, and fully compromise the affected system.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/cpulimit/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_cpulimit_privilege_escalation.yml)*
