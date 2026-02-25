# Linux AWK Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the use of the AWK command with elevated privileges to execute system commands. It leverages Endpoint Detection and Response (EDR) telemetry, specifically monitoring processes that include "sudo," "awk," and "BEGIN*system" in their command lines. This activity is significant because it indicates a potential privilege escalation attempt, where a user could gain root access by executing commands as the root user. If confirmed malicious, this could allow an attacker to fully compromise the system, execute arbitrary commands, and maintain persistent control over the affected endpoint.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/awk/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_awk_privilege_escalation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
