# Linux Auditd Data Transfer Size Limits Via Split

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious data transfer activities that involve the use of the `split` syscall, potentially indicating an attempt to evade detection by breaking large files into smaller parts. Attackers may use this technique to bypass size-based security controls, facilitating the covert exfiltration of sensitive data. By monitoring for unusual or unauthorized use of the `split` syscall, this analytic helps identify potential data exfiltration attempts, allowing security teams to intervene and prevent the unauthorized transfer of critical information from the network.

## MITRE ATT&CK

- T1030

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1030/linux_auditd_split_b_exec/auditd_execve_split.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_data_transfer_size_limits_via_split.yml)*
