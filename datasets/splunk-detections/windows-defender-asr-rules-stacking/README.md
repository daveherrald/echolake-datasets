# Windows Defender ASR Rules Stacking

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying security events from Microsoft Defender, focusing on Exploit Guard and Attack Surface Reduction (ASR) features. It detects Event IDs 1121, 1126, 1131, and 1133 for blocked operations, and Event IDs 1122, 1125, 1132, and 1134 for audit logs. Event ID 1129 indicates user overrides, while Event ID 5007 signals configuration changes. This detection uses a lookup to correlate ASR rule GUIDs with descriptive names. Monitoring these events is crucial for identifying unauthorized operations, potential security breaches, and policy enforcement issues. If confirmed malicious, attackers could bypass security measures, execute unauthorized actions, or alter system configurations.

## MITRE ATT&CK

- T1566.001
- T1566.002
- T1059

## Analytic Stories

- Windows Attack Surface Reduction

## Data Sources

- Windows Event Log Defender 1121
- Windows Event Log Defender 1122
- Windows Event Log Defender 1125
- Windows Event Log Defender 1126
- Windows Event Log Defender 1129
- Windows Event Log Defender 1131
- Windows Event Log Defender 1133
- Windows Event Log Defender 1134
- Windows Event Log Defender 5007

## Sample Data

- **Source:** WinEventLog:Microsoft-Windows-Windows Defender/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/defender/asr_defender_operational.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_defender_asr_rules_stacking.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
