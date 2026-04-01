# Linux Auditd Private Keys and Certificate Enumeration

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious attempts to find private keys, which may indicate an attacker's effort to access sensitive cryptographic information. Private keys are crucial for securing encrypted communications and data, and unauthorized access to them can lead to severe security breaches, including data decryption and identity theft. By monitoring for unusual or unauthorized searches for private keys, this analytic helps identify potential threats to cryptographic security, enabling security teams to take swift action to protect the integrity and confidentiality of encrypted information.

## MITRE ATT&CK

- T1552.004

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Execve

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.004/linux_auditd_find_gpg/auditd_execve_find_gpg.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_private_keys_and_certificate_enumeration.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
