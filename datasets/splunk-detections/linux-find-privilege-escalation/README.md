# Linux Find Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the use of the 'find' command with 'sudo' and '-exec' options, which can indicate an attempt to escalate privileges on a Linux system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line arguments. This activity is significant because it can allow a user to execute system commands as root, potentially leading to a root shell. If confirmed malicious, this could enable an attacker to gain full control over the system, leading to severe security breaches and unauthorized access to sensitive data.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/find/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_find_privilege_escalation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
