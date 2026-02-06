# Windows Defender ASR Audit Events

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This detection searches for Windows Defender ASR audit events. ASR is a feature of Windows Defender Exploit Guard that prevents actions and apps that are typically used by exploit-seeking malware to infect machines. ASR rules are applied to processes and applications. When a process or application attempts to perform an action that is blocked by an ASR rule, an event is generated. This detection searches for ASR audit events that are generated when a process or application attempts to perform an action that would be blocked by an ASR rule, but is allowed to proceed for auditing purposes.

## MITRE ATT&CK

- T1059
- T1566.001
- T1566.002

## Analytic Stories

- Windows Attack Surface Reduction

## Data Sources

- Windows Event Log Defender 1122
- Windows Event Log Defender 1125
- Windows Event Log Defender 1126
- Windows Event Log Defender 1132
- Windows Event Log Defender 1134

## Sample Data

- **Source:** WinEventLog:Microsoft-Windows-Windows Defender/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/defender/asr_audit.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_defender_asr_audit_events.yml)*
