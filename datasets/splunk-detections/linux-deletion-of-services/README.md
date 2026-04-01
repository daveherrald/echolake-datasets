# Linux Deletion Of Services

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the deletion of services on a Linux machine. It leverages filesystem event logs to identify when service files within system directories (e.g., /etc/systemd/, /lib/systemd/, /run/systemd/) are deleted. This activity is significant because attackers may delete or modify services to disable security features or evade defenses. If confirmed malicious, this behavior could indicate an attempt to impair system functionality or execute a destructive payload, potentially leading to system instability or data loss. Immediate investigation is required to determine the responsible process and user.

## MITRE ATT&CK

- T1070.004
- T1485

## Analytic Stories

- AwfulShred
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

*Source: [Splunk Security Content](detections/endpoint/linux_deletion_of_services.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
