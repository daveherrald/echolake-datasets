# Linux Auditd Install Kernel Module Using Modprobe Utility

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the installation of a Linux kernel module using the modprobe utility. It leverages data from Linux Auditd, focusing on process names and command-line executions. This activity is significant because installing a kernel module can indicate an attempt to deploy a rootkit or other malicious kernel-level code, potentially leading to elevated privileges and bypassing security detections. If confirmed malicious, this could allow an attacker to gain persistent, high-level access to the system, compromising its integrity and security.

## MITRE ATT&CK

- T1547.006

## Analytic Stories

- Linux Privilege Escalation
- Linux Rootkit
- Linux Persistence Techniques
- Compromised Linux Host
- China-Nexus Threat Activity

## Data Sources

- Linux Auditd Syscall

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.006/linux_auditd_modprobe_new/linux_auditd_new_modprobe.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_install_kernel_module_using_modprobe_utility.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
