# Linux Indicator Removal Clear Cache

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects processes that clear or free page cache on a Linux system. It leverages Endpoint Detection and Response (EDR) data, focusing on specific command-line executions involving the kernel system request `drop_caches`. This activity is significant as it may indicate an attempt to delete forensic evidence or the presence of wiper malware like Awfulshred. If confirmed malicious, this behavior could allow an attacker to cover their tracks, making it difficult to investigate other malicious activities or system compromises.

## MITRE ATT&CK

- T1070

## Analytic Stories

- AwfulShred
- Data Destruction

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/awfulshred/test3/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_indicator_removal_clear_cache.yml)*
