# Linux Auditd File And Directory Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious file and directory discovery activities, which may indicate an attacker's effort to locate sensitive documents and files on a compromised system. This behavior often precedes data exfiltration, as adversaries seek to identify valuable or confidential information for theft. By identifying unusual or unauthorized attempts to browse or enumerate files and directories, this analytic helps security teams detect potential reconnaissance or preparatory actions by an attacker, enabling timely intervention to prevent data breaches or unauthorized access.

## MITRE ATT&CK

- T1083

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1083/linux_auditd_find_document/auditd_execve_file_dir_discovery.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_file_and_directory_discovery.yml)*
