# Recursive Delete of Directory In Batch CMD

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of a batch command designed to recursively delete files or directories, a technique often used by ransomware like Reddot to delete files in the recycle bin and prevent recovery. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that include specific flags for recursive and quiet deletions. This activity is significant as it indicates potential ransomware behavior aimed at data destruction. If confirmed malicious, it could lead to significant data loss and hinder recovery efforts, severely impacting business operations.

## MITRE ATT&CK

- T1070.004

## Analytic Stories

- Ransomware
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/recursive_delete_of_directory_in_batch_cmd.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
