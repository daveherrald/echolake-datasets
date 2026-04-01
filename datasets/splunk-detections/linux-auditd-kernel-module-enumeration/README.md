# Linux Auditd Kernel Module Enumeration

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the use of the 'kmod' process to list kernel modules on a Linux system. This detection leverages data from Linux Auditd, focusing on process names and command-line executions. While listing kernel modules is not inherently malicious, it can be a precursor to loading unauthorized modules using 'insmod'. If confirmed malicious, this activity could allow an attacker to load kernel modules, potentially leading to privilege escalation, persistence, or other malicious actions within the system.

## MITRE ATT&CK

- T1082
- T1014

## Analytic Stories

- Compromised Linux Host
- XorDDos
- Linux Rootkit

## Data Sources

- Linux Auditd Syscall

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1082/linux_auditd_lsmod_new/linux_auditd_new_lsmod.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_kernel_module_enumeration.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
