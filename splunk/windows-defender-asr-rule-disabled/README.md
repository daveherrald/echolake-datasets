# Windows Defender ASR Rule Disabled

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies when a Windows Defender ASR rule disabled events. ASR is a feature of Windows Defender Exploit Guard that prevents actions and apps that are typically used by exploit-seeking malware to infect machines. ASR rules are applied to processes and applications. When a process or application attempts to perform an action that is blocked by an ASR rule, an event is generated. This detection searches for ASR rule disabled events that are generated when an ASR rule is disabled.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Windows Attack Surface Reduction

## Data Sources

- Windows Event Log Defender 5007

## Sample Data

- **Source:** WinEventLog:Microsoft-Windows-Windows Defender/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/defender/asr_disabled_registry.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_defender_asr_rule_disabled.yml)*
