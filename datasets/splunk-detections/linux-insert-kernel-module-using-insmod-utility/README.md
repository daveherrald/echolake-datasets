# Linux Insert Kernel Module Using Insmod Utility

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the insertion of a Linux kernel module using the insmod utility. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include process names and command-line details. This activity is significant as it may indicate the installation of a rootkit or malicious kernel module, potentially allowing an attacker to gain elevated privileges and bypass security detections. If confirmed malicious, this could lead to unauthorized code execution, persistent access, and severe compromise of the affected system.

## MITRE ATT&CK

- T1547.006

## Analytic Stories

- Linux Persistence Techniques
- XorDDos
- Linux Rootkit
- Linux Privilege Escalation

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.006/loading_linux_kernel_module/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_insert_kernel_module_using_insmod_utility.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
