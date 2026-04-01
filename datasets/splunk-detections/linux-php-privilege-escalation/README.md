# Linux PHP Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the execution of PHP commands with elevated privileges on a Linux system. It identifies instances where PHP is used in conjunction with 'sudo' and 'system' commands, indicating an attempt to run system commands as the root user. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command-line arguments. This activity is significant because it can indicate an attempt to escalate privileges, potentially leading to full root access. If confirmed malicious, this could allow an attacker to execute arbitrary commands with root privileges, compromising the entire system.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/php/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_php_privilege_escalation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
