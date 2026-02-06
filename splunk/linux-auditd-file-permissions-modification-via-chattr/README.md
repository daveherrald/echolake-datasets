# Linux Auditd File Permissions Modification Via Chattr

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious file permissions modifications using the chattr command, which may indicate an attacker attempting to manipulate file attributes to evade detection or prevent alteration. The chattr command can be used to make files immutable or restrict deletion, which can be leveraged to protect malicious files or disrupt system operations. By monitoring for unusual or unauthorized chattr usage, this analytic helps identify potential tampering with critical files, enabling security teams to quickly respond to and mitigate threats associated with unauthorized file attribute changes.

## MITRE ATT&CK

- T1222.002

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.002/linux_auditd_chattr_i/auditd_proctitle_chattr.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_file_permissions_modification_via_chattr.yml)*
