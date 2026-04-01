# Linux Auditd Kernel Module Using Rmmod Utility

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious use of the `rmmod` utility for kernel module removal, which may indicate an attacker attempt to unload critical or security-related kernel modules. The `rmmod` command is used to remove modules from the Linux kernel, and unauthorized use can be a tactic to disable security features, conceal malicious activities, or disrupt system operations. By monitoring for unusual or unauthorized `rmmod` activity, this analytic helps identify potential tampering with kernel modules, enabling security teams to take proactive measures to protect system integrity and security.

## MITRE ATT&CK

- T1547.006

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Syscall

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.006/linux_auditd_rmmod_new/linux_auditd_new_rmmod.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_kernel_module_using_rmmod_utility.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
