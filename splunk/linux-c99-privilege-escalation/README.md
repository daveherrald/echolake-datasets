# Linux c99 Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of the c99 utility with sudo privileges, which can lead to privilege escalation on Linux systems. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because it indicates a potential misuse of the c99 utility to gain root access, which is critical for maintaining system security. If confirmed malicious, this could allow an attacker to execute commands as root, potentially compromising the entire system and accessing sensitive information.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/c99/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_c99_privilege_escalation.yml)*
