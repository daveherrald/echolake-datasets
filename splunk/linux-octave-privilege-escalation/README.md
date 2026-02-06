# Linux Octave Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of GNU Octave with elevated privileges, specifically when it runs system commands via sudo. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command-line arguments that include "octave-cli," "--eval," "system," and "sudo." This activity is significant because it indicates a potential privilege escalation attempt, allowing a user to execute commands as root. If confirmed malicious, this could lead to full system compromise, enabling an attacker to gain root access and execute arbitrary commands, severely impacting system security and integrity.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/octave/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_octave_privilege_escalation.yml)*
