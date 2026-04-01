# Windows DISM Remove Defender

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of `dism.exe` to remove Windows Defender. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that include specific parameters for disabling and removing Windows Defender. This activity is significant because adversaries may disable Defender to evade detection and carry out further malicious actions undetected. If confirmed malicious, this could lead to the attacker gaining persistent access, executing additional payloads, or exfiltrating sensitive data without being intercepted by Windows Defender.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- CISA AA23-347A
- Compromised Windows Host
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon_dism.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dism_remove_defender.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
