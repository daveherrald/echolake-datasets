# Linux Auditd Service Restarted

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the restarting or re-enabling of services on Linux systems using the `systemctl` or `service` commands. It leverages data from Linux Auditd, focusing on process and command-line execution logs. This activity is significant as adversaries may use it to maintain persistence or execute unauthorized actions. If confirmed malicious, this behavior could lead to repeated execution of malicious payloads, unauthorized access, or data destruction. Security analysts should investigate these events to mitigate risks and prevent further compromise.

## MITRE ATT&CK

- T1053.006

## Analytic Stories

- AwfulShred
- Scheduled Tasks
- Linux Privilege Escalation
- Data Destruction
- Linux Persistence Techniques
- Linux Living Off The Land
- Gomir
- Compromised Linux Host

## Data Sources

- Linux Auditd Proctitle

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.006/linux_services_restart/auditd_proctitle_service_restart.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_service_restarted.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
