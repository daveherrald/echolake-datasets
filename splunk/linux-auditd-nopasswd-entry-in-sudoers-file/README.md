# Linux Auditd Nopasswd Entry In Sudoers File

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the addition of NOPASSWD entries to the /etc/sudoers file on Linux systems. It leverages Linux Auditd data to identify command lines containing "NOPASSWD:". This activity is significant because it allows users to execute commands with elevated privileges without requiring a password, which can be exploited by adversaries to maintain persistent, privileged access. If confirmed malicious, this could lead to unauthorized privilege escalation, persistent access, and potential compromise of sensitive data and system integrity.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Persistence Techniques
- Compromised Linux Host
- China-Nexus Threat Activity
- Salt Typhoon
- Linux Privilege Escalation

## Data Sources

- Linux Auditd Proctitle

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/linux_auditd_nopasswd/linux_auditd_nopasswd2.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_nopasswd_entry_in_sudoers_file.yml)*
