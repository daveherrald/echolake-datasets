# Linux Busybox Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the execution of BusyBox with sudo privileges, which can lead to privilege escalation on Linux systems. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where BusyBox is executed with both 'sh' and 'sudo' commands. This activity is significant because it indicates a user may be attempting to gain root access, bypassing standard security controls. If confirmed malicious, this could allow an attacker to execute arbitrary commands as root, leading to full system compromise and potential persistence within the environment.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/busybox/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_busybox_privilege_escalation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
