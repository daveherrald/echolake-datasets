# Linux File Created In Kernel Driver Directory

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of files in the Linux kernel/driver directory. It leverages filesystem data to identify new files in this critical directory. This activity is significant because the kernel/driver directory is typically reserved for kernel modules, and unauthorized file creation here can indicate a rootkit installation. If confirmed malicious, this could allow an attacker to gain high-level privileges, potentially compromising the entire system by executing code at the kernel level.

## MITRE ATT&CK

- T1547.006

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Rootkit

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.006/loading_linux_kernel_module/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_file_created_in_kernel_driver_directory.yml)*
