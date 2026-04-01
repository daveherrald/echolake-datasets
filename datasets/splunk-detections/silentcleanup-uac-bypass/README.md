# SilentCleanup UAC Bypass

**Type:** TTP

**Author:** Steven Dick, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious modifications to the registry that may indicate a UAC (User Account Control) bypass attempt via the SilentCleanup task. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on registry changes in the path "*\\Environment\\windir" with executable values. This activity is significant as it can allow an attacker to gain high-privilege execution without user consent, bypassing UAC protections. If confirmed malicious, this could lead to unauthorized administrative access, enabling further system compromise and persistence.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse
- MoonPeak

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/silentcleanup_uac_bypass.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
