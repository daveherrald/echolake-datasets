# Linux Auditd Find Credentials From Password Stores

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious attempts to find credentials stored in password stores, indicating a potential attacker's effort to access sensitive login information. Password stores are critical repositories that contain valuable credentials, and unauthorized access to them can lead to significant security breaches. By monitoring for unusual or unauthorized activities related to password store access, this analytic helps identify potential credential theft attempts, allowing security teams to respond promptly and prevent unauthorized access to critical systems and data.

## MITRE ATT&CK

- T1555.005

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host
- Scattered Lapsus$ Hunters
- Hellcat Ransomware

## Data Sources

- Linux Auditd Execve

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555.005/linux_auditd_find_credentials/auditd_execve_find_creds.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_find_credentials_from_password_stores.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
