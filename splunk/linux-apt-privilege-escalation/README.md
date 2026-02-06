# Linux APT Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the use of the Advanced Package Tool (APT) with elevated privileges via sudo on Linux systems. It leverages Endpoint Detection and Response (EDR) telemetry to identify processes where APT commands are executed with sudo rights. This activity is significant because it indicates a user can run system commands as root, potentially leading to unauthorized root shell access. If confirmed malicious, this could allow an attacker to escalate privileges, execute arbitrary commands, and gain full control over the affected system, posing a severe security risk.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/apt/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_apt_privilege_escalation.yml)*
