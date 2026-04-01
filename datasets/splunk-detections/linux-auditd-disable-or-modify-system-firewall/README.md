# Linux Auditd Disable Or Modify System Firewall

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the suspicious disable or modify system firewall. This behavior is critical for a SOC to monitor because it may indicate attempts to gain unauthorized access or maintain control over a system. Such actions could be signs of malicious activity. If confirmed, this could lead to serious consequences, including a compromised system, unauthorized access to sensitive data, or even a wider breach affecting the entire network. Detecting and responding to these signs early is essential to prevent potential security incidents.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Service Stop

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/linux_auditd_disable_firewall/linux_auditd_disable_firewall.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_disable_or_modify_system_firewall.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
