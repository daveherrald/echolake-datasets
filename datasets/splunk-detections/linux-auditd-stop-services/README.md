# Linux Auditd Stop Services

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting attempts to stop a service on Linux systems. It leverages data from Linux Auditd. This activity is significant as adversaries often stop or terminate security or critical services to disable defenses or disrupt operations, as seen in malware like Industroyer2. If confirmed malicious, this could lead to the disabling of security mechanisms, allowing attackers to persist, escalate privileges, or deploy destructive payloads, severely impacting system integrity and availability.

## MITRE ATT&CK

- T1489

## Analytic Stories

- Industroyer2
- Data Destruction
- AwfulShred
- Compromised Linux Host

## Data Sources

- Linux Auditd Service Stop

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1489/linux_auditd_service_stop/linux_auditd_service_stop.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_stop_services.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
