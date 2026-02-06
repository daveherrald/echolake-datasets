# Linux Auditd Insert Kernel Module Using Insmod Utility

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the insertion of a Linux kernel module using the insmod utility. It leverages data from Linux Auditd, focusing on process execution logs that include process names and command-line details. This activity is significant as it may indicate the installation of a rootkit or malicious kernel module, potentially allowing an attacker to gain elevated privileges and bypass security detections. If confirmed malicious, this could lead to unauthorized code execution, persistent access, and severe compromise of the affected system.

## MITRE ATT&CK

- T1547.006

## Analytic Stories

- XorDDos
- Linux Rootkit
- Compromised Linux Host
- Linux Privilege Escalation
- Linux Persistence Techniques

## Data Sources

- Linux Auditd Syscall

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.006/linux_auditd_insmod_new/linux_auditd_new_insmod.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_insert_kernel_module_using_insmod_utility.yml)*
