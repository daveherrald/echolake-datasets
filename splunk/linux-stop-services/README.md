# Linux Stop Services

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects attempts to stop or clear a service on Linux systems. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on processes like "systemctl," "service," and "svcadm" executing stop commands. This activity is significant as adversaries often terminate security or critical services to disable defenses or disrupt operations, as seen in malware like Industroyer2. If confirmed malicious, this could lead to the disabling of security mechanisms, allowing attackers to persist, escalate privileges, or deploy destructive payloads, severely impacting system integrity and availability.

## MITRE ATT&CK

- T1489

## Analytic Stories

- AwfulShred
- Data Destruction
- Industroyer2

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1489/linux_service_stop_disable/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_stop_services.yml)*
