# USN Journal Deletion

**Type:** TTP

**Author:** David Dorsey, Splunk

## Description

The following analytic detects the deletion of the USN Journal using the fsutil.exe utility. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because the USN Journal maintains a log of all changes made to files on the disk, and its deletion can be an indicator of an attempt to cover tracks or hinder forensic investigations. If confirmed malicious, this action could allow an attacker to obscure their activities, making it difficult to trace file modifications and potentially compromising incident response efforts.

## MITRE ATT&CK

- T1070

## Analytic Stories

- Windows Log Manipulation
- Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/usn_journal_deletion.yml)*
