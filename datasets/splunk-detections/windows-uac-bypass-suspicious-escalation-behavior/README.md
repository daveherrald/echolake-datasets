# Windows UAC Bypass Suspicious Escalation Behavior

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting when a process spawns an executable known for User Account Control (UAC) bypass exploitation and subsequently monitors for any child processes with a higher integrity level than the original process. This detection leverages Sysmon EventID 1 data, focusing on process integrity levels and known UAC bypass executables. This activity is significant as it may indicate an attacker has successfully used a UAC bypass exploit to escalate privileges. If confirmed malicious, the attacker could gain elevated privileges, potentially leading to further system compromise and persistent access.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Living Off The Land
- Compromised Windows Host
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/uac_behavior/uac_behavior_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_uac_bypass_suspicious_escalation_behavior.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
