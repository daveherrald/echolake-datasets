# Linux Service Started Or Enabled

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation or enabling of services on Linux platforms using the systemctl or service tools. It leverages Endpoint Detection and Response (EDR) logs, focusing on process names, parent processes, and command-line executions. This activity is significant as adversaries may create or modify services to maintain persistence or execute malicious payloads. If confirmed malicious, this behavior could lead to persistent access, data theft, ransomware deployment, or other damaging outcomes. Monitoring and investigating such activities are crucial for maintaining the security and integrity of the environment.

## MITRE ATT&CK

- T1053.006

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Living Off The Land
- Scheduled Tasks
- Gomir

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.006/service_systemd/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_service_started_or_enabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
