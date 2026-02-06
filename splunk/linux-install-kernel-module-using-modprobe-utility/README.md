# Linux Install Kernel Module Using Modprobe Utility

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the installation of a Linux kernel module using the modprobe utility. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because installing a kernel module can indicate an attempt to deploy a rootkit or other malicious kernel-level code, potentially leading to elevated privileges and bypassing security detections. If confirmed malicious, this could allow an attacker to gain persistent, high-level access to the system, compromising its integrity and security.

## MITRE ATT&CK

- T1547.006

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Rootkit
- China-Nexus Threat Activity
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.006/loading_linux_kernel_module/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_install_kernel_module_using_modprobe_utility.yml)*
