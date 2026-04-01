# Linux Auditd Hardware Addition Swapoff

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the "swapoff" command, which disables the swapping of paging devices on a Linux system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. This activity is significant because disabling swap can be a tactic used by malware, such as Awfulshred, to evade detection and hinder forensic analysis. If confirmed malicious, this action could allow an attacker to manipulate system memory management, potentially leading to data corruption, system instability, or evasion of memory-based detection mechanisms.

## MITRE ATT&CK

- T1200

## Analytic Stories

- Data Destruction
- AwfulShred
- Compromised Linux Host
- Scattered Lapsus$ Hunters

## Data Sources

- Linux Auditd Execve

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1200/linux_auditd_swapoff/linux_auditd_swapoff2.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_hardware_addition_swapoff.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
