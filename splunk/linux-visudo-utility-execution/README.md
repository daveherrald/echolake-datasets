# Linux Visudo Utility Execution

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the 'visudo' utility to modify the /etc/sudoers file on a Linux system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. This activity is significant because unauthorized changes to the /etc/sudoers file can grant elevated privileges to users, potentially allowing adversaries to execute commands as root. If confirmed malicious, this could lead to full system compromise, privilege escalation, and persistent unauthorized access, severely impacting the security posture of the affected host.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/visudo/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_visudo_utility_execution.yml)*
