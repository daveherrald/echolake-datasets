# Linux NOPASSWD Entry In Sudoers File

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the addition of NOPASSWD entries to the /etc/sudoers file on Linux systems. It leverages Endpoint Detection and Response (EDR) telemetry to identify command lines containing "NOPASSWD:". This activity is significant because it allows users to execute commands with elevated privileges without requiring a password, which can be exploited by adversaries to maintain persistent, privileged access. If confirmed malicious, this could lead to unauthorized privilege escalation, persistent access, and potential compromise of sensitive data and system integrity.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Persistence Techniques
- China-Nexus Threat Activity
- Salt Typhoon
- Linux Privilege Escalation

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/nopasswd_sudoers/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_nopasswd_entry_in_sudoers_file.yml)*
