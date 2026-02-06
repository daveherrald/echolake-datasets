# Linux Docker Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects attempts to escalate privileges on a Linux system using Docker. It identifies processes where Docker commands are used to mount the root directory or execute shell commands within a container. This detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process names, command-line arguments, and parent processes. This activity is significant because it can allow an attacker with Docker privileges to modify critical system files, such as /etc/passwd, to create a superuser. If confirmed malicious, this could lead to full system compromise and persistent unauthorized access.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/docker/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_docker_privilege_escalation.yml)*
