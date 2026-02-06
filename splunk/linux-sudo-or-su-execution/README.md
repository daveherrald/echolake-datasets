# Linux Sudo OR Su Execution

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the "sudo" or "su" command on a Linux operating system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and parent process names. This activity is significant because "sudo" and "su" commands are commonly used by adversaries to elevate privileges, potentially leading to unauthorized access or control over the system. If confirmed malicious, this activity could allow attackers to execute commands with root privileges, leading to severe security breaches, data exfiltration, or further system compromise.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/sudo_su/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_sudo_or_su_execution.yml)*
