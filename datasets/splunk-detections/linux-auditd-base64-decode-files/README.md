# Linux Auditd Base64 Decode Files

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious Base64 decode operations that may indicate malicious activity, such as data exfiltration or execution of encoded commands. Base64 is commonly used to encode data for safe transmission, but attackers may abuse it to conceal malicious payloads. This detection focuses on identifying unusual or unexpected Base64 decoding processes, particularly when associated with critical files or directories. By monitoring these activities, the analytic helps uncover potential threats, enabling security teams to respond promptly and mitigate risks associated with encoded malware or unauthorized data access.

## MITRE ATT&CK

- T1140

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1140/linux_auditd_base64/auditd_execve_base64.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_base64_decode_files.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
