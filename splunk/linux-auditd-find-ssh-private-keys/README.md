# Linux Auditd Find Ssh Private Keys

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious attempts to find SSH private keys, which may indicate an attacker's effort to compromise secure access to systems. SSH private keys are essential for secure authentication, and unauthorized access to these keys can enable attackers to gain unauthorized access to servers and other critical infrastructure. By monitoring for unusual or unauthorized searches for SSH private keys, this analytic helps identify potential threats to network security, allowing security teams to quickly respond and safeguard against unauthorized access and potential breaches.

## MITRE ATT&CK

- T1552.004

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host
- Hellcat Ransomware

## Data Sources

- Linux Auditd Execve

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.004/linux_auditd_find_ssh_files/auditd_execve_find_ssh.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_find_ssh_private_keys.yml)*
