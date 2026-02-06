# Linux Deletion Of Init Daemon Script

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the deletion of init daemon scripts on a Linux machine. It leverages filesystem event logs to identify when files within the /etc/init.d/ directory are deleted. This activity is significant because init daemon scripts control the start and stop of critical services, and their deletion can indicate an attempt to impair security features or evade defenses. If confirmed malicious, this behavior could allow an attacker to disrupt essential services, execute destructive payloads, or persist undetected in the environment.

## MITRE ATT&CK

- T1070.004
- T1485

## Analytic Stories

- AcidRain
- Data Destruction
- AcidPour

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/acidrain/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_deletion_of_init_daemon_script.yml)*
