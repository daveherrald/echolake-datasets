# Linux Service File Created In Systemd Directory

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of suspicious service files within the systemd directories on Linux platforms. It leverages logs containing file name, file path, and process GUID data from endpoints. This activity is significant for a SOC as it may indicate an adversary attempting to establish persistence on a compromised host. If confirmed malicious, this could lead to system compromise or data exfiltration, allowing attackers to maintain control over the system and execute further malicious activities.

## MITRE ATT&CK

- T1053.006

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Living Off The Land
- Scheduled Tasks
- Gomir
- China-Nexus Threat Activity
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.006/service_systemd/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_service_file_created_in_systemd_directory.yml)*
