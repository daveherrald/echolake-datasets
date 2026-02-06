# Linux Ruby Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of Ruby commands with elevated privileges on a Linux system. It identifies processes where Ruby is used with the `-e` flag to execute commands via `sudo`, leveraging Endpoint Detection and Response (EDR) telemetry. This activity is significant because it indicates a potential privilege escalation attempt, allowing a user to execute commands as root. If confirmed malicious, this could lead to full system compromise, enabling an attacker to gain root access, execute arbitrary commands, and maintain persistent control over the affected system.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/ruby/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_ruby_privilege_escalation.yml)*
