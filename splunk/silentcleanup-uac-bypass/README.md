# SilentCleanup UAC Bypass

**Type:** TTP

**Author:** Steven Dick, Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious modifications to the registry that may indicate a UAC (User Account Control) bypass attempt via the SilentCleanup task. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on registry changes in the path "*\\Environment\\windir" with executable values. This activity is significant as it can allow an attacker to gain high-privilege execution without user consent, bypassing UAC protections. If confirmed malicious, this could lead to unauthorized administrative access, enabling further system compromise and persistence.

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
