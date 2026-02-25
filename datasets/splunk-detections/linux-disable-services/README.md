# Linux Disable Services

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting attempts to disable a service on a Linux system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on processes like "systemctl," "service," and "svcadm" with commands containing "disable." This activity is significant as adversaries may disable security or critical services to evade detection and facilitate further malicious actions, such as deploying destructive payloads. If confirmed malicious, this could lead to the termination of essential security services, allowing attackers to persist undetected and potentially cause significant damage to the system.

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

*Source: [Splunk Security Content](detections/endpoint/linux_disable_services.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
