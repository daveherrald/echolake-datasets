# Linux OpenVPN Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the execution of OpenVPN with elevated privileges, specifically when combined with the `--dev`, `--script-security`, `--up`, and `sudo` options. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command-line arguments and execution details. This activity is significant because it indicates a potential privilege escalation attempt, allowing a user to execute system commands as root. If confirmed malicious, this could lead to full system compromise, enabling an attacker to gain root access and execute arbitrary commands with elevated privileges.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/openvpn/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_openvpn_privilege_escalation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
