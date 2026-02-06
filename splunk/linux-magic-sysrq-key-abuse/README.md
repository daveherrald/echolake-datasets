# Linux Magic SysRq Key Abuse

**Type:** TTP

**Author:** Milad Cheraghi

## Description

Detects potential abuse of the Linux Magic SysRq (System Request) key by adversaries with root or sufficient privileges to manipulate or destabilize a system.
Writing to /proc/sysrq-trigger can crash the system, kill processes, or bypass standard logging.
Monitoring SysRq abuse helps detect stealthy post-exploitation activity.
Correlate with related EXECVE or PROCTITLE events to identify the process or user responsible for the access or modification.


## MITRE ATT&CK

- T1059.004
- T1529
- T1489
- T1499

## Analytic Stories

- Compromised Linux Host

## Data Sources

- Linux Auditd Path
- Linux Auditd Cwd

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1529/auditd_path_sysrq/path_sysrq.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_magic_sysrq_key_abuse.yml)*
