# Linux Auditd Setuid Using Chmod Utility

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the chmod utility to set the SUID or SGID bit on files, which can allow users to temporarily gain root or group-level access. This detection leverages data from Linux Auditd, focusing on process names and command-line arguments related to chmod. This activity is significant as it can indicate an attempt to escalate privileges or maintain persistence on a system. If confirmed malicious, an attacker could gain elevated access, potentially compromising sensitive data or critical system functions.

## MITRE ATT&CK

- T1548.001

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Proctitle

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.001/linux_auditd_setuid/auditd_proctitle_setuid.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_setuid_using_chmod_utility.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
