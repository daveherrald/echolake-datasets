# Linux Auditd Unload Module Via Modprobe

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious use of the `modprobe` command to unload kernel modules, which may indicate an attempt to disable critical system components or evade detection. The `modprobe` utility manages kernel modules, and unauthorized unloading of modules can disrupt system security features, remove logging capabilities, or conceal malicious activities. By monitoring for unusual or unauthorized `modprobe` operations involving module unloading, this analytic helps identify potential tampering with kernel functionality, enabling security teams to investigate and address possible threats to system integrity.

## MITRE ATT&CK

- T1547.006

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.006/linux_auditd_modprobe_unload_module/auditd_execve_modprobe.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_unload_module_via_modprobe.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
