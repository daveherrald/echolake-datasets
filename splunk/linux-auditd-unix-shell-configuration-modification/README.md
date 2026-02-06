# Linux Auditd Unix Shell Configuration Modification

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious access or modifications to Unix shell configuration files, which may indicate an attempt to alter system behavior or gain unauthorized access.
Unix shell configuration files, such as `.bashrc` or `.profile`, control user environment settings and command execution.
Unauthorized changes to these files can be used to execute malicious commands, escalate privileges, or hide malicious activities.
By monitoring for unusual or unauthorized modifications to shell configuration files, this analytic helps identify potential security threats, allowing security teams to respond quickly and mitigate risks.
Correlate this with related EXECVE or PROCTITLE events to identify the process or user responsible for the access or modification.


## MITRE ATT&CK

- T1546.004

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Path
- Linux Auditd Cwd

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.004/linux_auditd_unix_shell_mod_config//linux_path_profile_d.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_unix_shell_configuration_modification.yml)*
