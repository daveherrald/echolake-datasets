# Linux Make Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the use of the 'make' command with elevated privileges to execute system commands as root, potentially leading to a root shell. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that include 'make', '--eval', and 'sudo'. This activity is significant because it indicates a possible privilege escalation attempt, allowing a user to gain root access. If confirmed malicious, an attacker could achieve full control over the system, execute arbitrary commands, and compromise the entire environment.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/make/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_make_privilege_escalation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
