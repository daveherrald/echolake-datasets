# Linux Sqlite3 Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of the sqlite3 command with elevated privileges, which can be exploited for privilege escalation. It leverages Endpoint Detection and Response (EDR) telemetry to identify instances where sqlite3 is used in conjunction with shell commands and sudo. This activity is significant because it indicates a potential attempt to gain root access, which could lead to full system compromise. If confirmed malicious, an attacker could execute arbitrary commands as root, leading to unauthorized access, data exfiltration, or further lateral movement within the network.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/sqlite3/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_sqlite3_privilege_escalation.yml)*
