# Windows Defender ASR Block Events

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This detection searches for Windows Defender ASR block events. ASR is a feature of Windows Defender Exploit Guard that prevents actions and apps that are typically used by exploit-seeking malware to infect machines. ASR rules are applied to processes and applications. When a process or application attempts to perform an action that is blocked by an ASR rule, an event is generated. This detection searches for ASR block events that are generated when a process or application attempts to perform an action that is blocked by an ASR rule. Typically, these will be enabled in block most after auditing and tuning the ASR rules themselves. Set to TTP once tuned.

## MITRE ATT&CK

- T1059
- T1566.001
- T1566.002

## Analytic Stories

- Windows Attack Surface Reduction

## Data Sources

- Windows Event Log Defender 1121
- Windows Event Log Defender 1126
- Windows Event Log Defender 1129
- Windows Event Log Defender 1131
- Windows Event Log Defender 1133

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/defender/asr_block.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_defender_asr_block_events.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
