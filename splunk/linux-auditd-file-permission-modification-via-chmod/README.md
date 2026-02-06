# Linux Auditd File Permission Modification Via Chmod

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Ivar Nygård

## Description

The following analytic detects suspicious file permission modifications using the `chmod` command, which may indicate an attacker attempting to alter access controls on critical files or directories. Such modifications can be used to grant unauthorized users elevated privileges or to conceal malicious activities by restricting legitimate access. By monitoring for unusual or unauthorized `chmod` usage, this analytic helps identify potential security breaches, allowing security teams to respond promptly to prevent privilege escalation, data tampering, or other unauthorized actions on the system.

## MITRE ATT&CK

- T1222.002

## Analytic Stories

- Linux Persistence Techniques
- Compromised Linux Host
- China-Nexus Threat Activity
- Linux Living Off The Land
- XorDDos
- Salt Typhoon
- Linux Privilege Escalation

## Data Sources

- Linux Auditd Proctitle

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.002/linux_auditd_chmod_exec_attrib/auditd_proctitle_chmod.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_file_permission_modification_via_chmod.yml)*
