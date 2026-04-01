# Windows User Deletion Via Net

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of net.exe or net1.exe command-line to delete a user account on a system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line execution logs. This activity is significant as it may indicate an attempt to impair user accounts or cover tracks during lateral movement. If confirmed malicious, this could lead to unauthorized access removal, disruption of legitimate user activities, or concealment of adversarial actions, complicating incident response and forensic investigations.

## MITRE ATT&CK

- T1531

## Analytic Stories

- XMRig
- Graceful Wipe Out Attack
- DarkGate Malware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_user_deletion_via_net.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
