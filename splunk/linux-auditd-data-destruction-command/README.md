# Linux Auditd Data Destruction Command

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of a Unix shell command designed to wipe root directories on a Linux host. It leverages data from Linux Auditd, focusing on the 'rm' command with force recursive deletion and the '--no-preserve-root' option. This activity is significant as it indicates potential data destruction attempts, often associated with malware like Awfulshred. If confirmed malicious, this behavior could lead to severe data loss, system instability, and compromised integrity of the affected Linux host. Immediate investigation and response are crucial to mitigate potential damage.

## MITRE ATT&CK

- T1485

## Analytic Stories

- Data Destruction
- AwfulShred
- Compromised Linux Host

## Data Sources

- Linux Auditd Proctitle

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/linux_auditd_no_preserve_root/auditd_proctitle_rm_rf.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_data_destruction_command.yml)*
