# Linux Auditd Shred Overwrite Command

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the 'shred' command on a Linux machine, which is used to overwrite files to make them unrecoverable. It leverages data from Linux Auditd, focusing on process names and command-line arguments. This activity is significant because the 'shred' command can be used in destructive attacks, such as those seen in the Industroyer2 malware targeting energy facilities. If confirmed malicious, this activity could lead to the permanent destruction of critical files, severely impacting system integrity and data availability.

## MITRE ATT&CK

- T1485

## Analytic Stories

- AwfulShred
- Linux Privilege Escalation
- Data Destruction
- Linux Persistence Techniques
- Industroyer2
- Compromised Linux Host

## Data Sources

- Linux Auditd Proctitle

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/linux_auditd_shred/auditd_proctitle_shred.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_shred_overwrite_command.yml)*
