# Linux c89 Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of the 'c89' command with elevated privileges, which can be used to compile and execute C programs as root. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events that include command-line arguments. This activity is significant because it indicates a potential privilege escalation attempt, allowing a user to execute arbitrary commands as root. If confirmed malicious, this could lead to full system compromise, enabling the attacker to gain root access and execute any command with elevated privileges.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/c89/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_c89_privilege_escalation.yml)*
