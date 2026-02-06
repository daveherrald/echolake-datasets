# Linux Hardware Addition SwapOff

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the "swapoff" command, which disables the swapping of paging devices on a Linux system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. This activity is significant because disabling swap can be a tactic used by malware, such as Awfulshred, to evade detection and hinder forensic analysis. If confirmed malicious, this action could allow an attacker to manipulate system memory management, potentially leading to data corruption, system instability, or evasion of memory-based detection mechanisms.

## MITRE ATT&CK

- T1200

## Analytic Stories

- AwfulShred
- Data Destruction
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/awfulshred/test1/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_hardware_addition_swapoff.yml)*
