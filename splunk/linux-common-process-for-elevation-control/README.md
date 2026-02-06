# Linux Common Process For Elevation Control

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the execution of common Linux processes used for elevation control, such as `chmod`, `chown`, and `setuid`. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because these processes are often abused by adversaries to gain persistence or escalate privileges on compromised hosts. If confirmed malicious, this behavior could allow attackers to modify file attributes, change file ownership, or set user IDs, potentially leading to unauthorized access and control over critical system resources.

## MITRE ATT&CK

- T1548.001

## Analytic Stories

- Linux Persistence Techniques
- China-Nexus Threat Activity
- Linux Living Off The Land
- Salt Typhoon
- Linux Privilege Escalation

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.001/chmod_uid/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_common_process_for_elevation_control.yml)*
