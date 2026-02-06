# Linux RPM Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of the RPM Package Manager with elevated privileges, specifically when it is used to run system commands as root via the `--eval` and `lua:os.execute` options. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process metadata. This activity is significant because it indicates a potential privilege escalation attempt, allowing a user to gain root access. If confirmed malicious, this could lead to full system compromise, unauthorized access to sensitive data, and further exploitation of the environment.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/rpm/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_rpm_privilege_escalation.yml)*
