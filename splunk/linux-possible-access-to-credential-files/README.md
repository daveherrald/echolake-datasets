# Linux Possible Access To Credential Files

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects attempts to access or dump the contents of /etc/passwd and /etc/shadow files on Linux systems. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on processes like 'cat', 'nano', 'vim', and 'vi' accessing these files. This activity is significant as it may indicate credential dumping, a technique used by adversaries to gain persistence or escalate privileges. If confirmed malicious, attackers could obtain hashed passwords for offline cracking, leading to unauthorized access and potential system compromise.

## MITRE ATT&CK

- T1003.008

## Analytic Stories

- Linux Persistence Techniques
- China-Nexus Threat Activity
- XorDDos
- Salt Typhoon
- Linux Privilege Escalation

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.008/copy_file_stdoutpipe/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_possible_access_to_credential_files.yml)*
