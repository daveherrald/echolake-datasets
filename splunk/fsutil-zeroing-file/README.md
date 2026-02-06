# Fsutil Zeroing File

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the 'fsutil' command with the 'setzerodata' parameter, which zeros out a target file. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because it is a technique used by ransomware, such as LockBit, to evade detection by erasing its malware path after encrypting the host. If confirmed malicious, this action could hinder forensic investigations and allow attackers to cover their tracks, complicating incident response efforts.

## MITRE ATT&CK

- T1070

## Analytic Stories

- Ransomware
- LockBit Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070/fsutil_file_zero/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/fsutil_zeroing_file.yml)*
