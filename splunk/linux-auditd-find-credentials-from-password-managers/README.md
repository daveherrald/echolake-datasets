# Linux Auditd Find Credentials From Password Managers

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious attempts to find credentials stored in password managers, which may indicate an attacker's effort to retrieve sensitive login information. Password managers are often targeted by adversaries seeking to access stored passwords for further compromise or lateral movement within a network. By monitoring for unusual or unauthorized access to password manager files or processes, this analytic helps identify potential credential theft attempts, enabling security teams to respond quickly to protect critical accounts and prevent further unauthorized access.

## MITRE ATT&CK

- T1555.005

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host
- Scattered Lapsus$ Hunters

## Data Sources

- Linux Auditd Execve

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555.005/linux_auditd_find_password_db/auditd_execve_pwd_mgr.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_find_credentials_from_password_managers.yml)*
