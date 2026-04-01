# Linux Auditd Whoami User Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the suspicious use of the whoami command, which may indicate an attacker trying to gather information about the current user account on a compromised system. The whoami command is commonly used to verify user privileges and identity, especially during initial stages of an attack to assess the level of access. By monitoring for unusual or unauthorized executions of whoami, this analytic helps in identifying potential reconnaissance activities, enabling security teams to take action before the attacker escalates privileges or conducts further malicious operations.

## MITRE ATT&CK

- T1033

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Syscall

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/linux_auditd_whoami_new/linux_auditd_new_whoami.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_whoami_user_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
