# Linux Puppet Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of Puppet commands with elevated privileges, specifically when Puppet is used to apply configurations with sudo rights. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because it indicates a potential privilege escalation attempt, where a user could gain root access and execute system commands as the root user. If confirmed malicious, this could allow an attacker to fully compromise the system, execute arbitrary commands, and maintain persistent control.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/puppet/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_puppet_privilege_escalation.yml)*
