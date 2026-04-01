# Windows Excessive Usage Of Net App

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting excessive usage of `net.exe` within a one-minute interval. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, parent processes, and command-line executions. This behavior is significant as it may indicate an adversary attempting to create, delete, or disable multiple user accounts rapidly, a tactic observed in Monero mining incidents. If confirmed malicious, this activity could lead to unauthorized user account manipulation, potentially compromising system integrity and enabling further malicious actions.

## MITRE ATT&CK

- T1531

## Analytic Stories

- Prestige Ransomware
- Graceful Wipe Out Attack
- XMRig
- Windows Post-Exploitation
- Azorult
- Ransomware
- Rhysida Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_excessive_usage_of_net_app.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
