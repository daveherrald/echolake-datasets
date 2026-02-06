# Linux Service Restarted

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the restarting or re-enabling of services on Linux systems using the `systemctl` or `service` commands. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line execution logs. This activity is significant as adversaries may use it to maintain persistence or execute unauthorized actions. If confirmed malicious, this behavior could lead to repeated execution of malicious payloads, unauthorized access, or data destruction. Security analysts should investigate these events to mitigate risks and prevent further compromise.

## MITRE ATT&CK

- T1053.006

## Analytic Stories

- AwfulShred
- Linux Privilege Escalation
- Linux Living Off The Land
- Data Destruction
- Linux Persistence Techniques
- Scheduled Tasks
- Gomir

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.006/service_systemd/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_service_restarted.yml)*
