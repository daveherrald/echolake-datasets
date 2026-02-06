# Linux apt-get Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Bhavin Patel, Splunk

## Description

The following analytic detects the execution of the 'apt-get' command with elevated privileges using 'sudo' on a Linux system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because it indicates a user may be attempting to escalate privileges to root, which could lead to unauthorized system control. If confirmed malicious, an attacker could gain root access, allowing them to execute arbitrary commands, install or remove software, and potentially compromise the entire system.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Living Off The Land
- Cisco Isovalent Suspicious Activity

## Data Sources

- Sysmon for Linux EventID 1
- Cisco Isovalent Process Exec

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/apt_get/sysmon_linux.log

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/apt_get/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_apt_get_privilege_escalation.yml)*
