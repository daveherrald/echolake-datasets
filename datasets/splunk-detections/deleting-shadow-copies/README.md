# Deleting Shadow Copies

**Type:** TTP

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for detecting the deletion of shadow copies using the vssadmin.exe or wmic.exe utilities. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because deleting shadow copies is a common tactic used by attackers to prevent recovery and hide their tracks. If confirmed malicious, this action could hinder incident response efforts and allow attackers to maintain persistence and cover their activities, making it crucial for security teams to investigate promptly.

## MITRE ATT&CK

- T1490

## Analytic Stories

- Rhysida Ransomware
- Prestige Ransomware
- CISA AA22-264A
- LockBit Ransomware
- SamSam Ransomware
- Chaos Ransomware
- Black Basta Ransomware
- DarkGate Malware
- Ransomware
- Windows Log Manipulation
- Compromised Windows Host
- Clop Ransomware
- Cactus Ransomware
- Medusa Ransomware
- VanHelsing Ransomware
- Termite Ransomware
- Storm-2460 CLFS Zero Day Exploitation

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/deleting_shadow_copies.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
