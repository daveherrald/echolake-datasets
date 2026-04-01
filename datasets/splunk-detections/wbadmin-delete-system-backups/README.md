# WBAdmin Delete System Backups

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of wbadmin.exe with flags that delete backup files, specifically targeting catalog or system state backups. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because it is commonly used by ransomware to prevent recovery by deleting system backups. If confirmed malicious, this action could severely hinder recovery efforts, leading to prolonged downtime and potential data loss.

## MITRE ATT&CK

- T1490

## Analytic Stories

- Ryuk Ransomware
- Ransomware
- Prestige Ransomware
- Chaos Ransomware
- Storm-2460 CLFS Zero Day Exploitation
- Storm-0501 Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/wbadmin_delete_system_backups.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
