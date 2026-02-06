# Linux Account Manipulation Of SSH Config and Keys

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the deletion of SSH keys on a Linux machine. It leverages filesystem event logs to identify when files within "/etc/ssh/*" or "~/.ssh/*" are deleted. This activity is significant because attackers may delete or modify SSH keys to evade security measures or as part of a destructive payload, similar to the AcidRain malware. If confirmed malicious, this behavior could lead to impaired security features, hindered forensic investigations, or further unauthorized access, necessitating immediate investigation to identify the responsible process and user.

## MITRE ATT&CK

- T1070.004
- T1485

## Analytic Stories

- AcidRain
- Hellcat Ransomware

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/acidrain/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_account_manipulation_of_ssh_config_and_keys.yml)*
