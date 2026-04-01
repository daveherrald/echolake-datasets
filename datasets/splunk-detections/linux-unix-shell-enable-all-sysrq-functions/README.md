# Linux Unix Shell Enable All SysRq Functions

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of a command to enable all SysRq functions on a Linux system, a technique associated with the AwfulShred malware. It leverages Endpoint Detection and Response (EDR) data to identify processes executing the command to pipe bitmask '1' to /proc/sys/kernel/sysrq. This activity is significant as it can indicate an attempt to manipulate kernel system requests, which is uncommon and potentially malicious. If confirmed, this could allow an attacker to reboot the system or perform other critical actions, leading to system instability or further compromise.

## MITRE ATT&CK

- T1059.004

## Analytic Stories

- AwfulShred
- Data Destruction

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/awfulshred/test2/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_unix_shell_enable_all_sysrq_functions.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
