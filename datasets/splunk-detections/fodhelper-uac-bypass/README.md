# FodHelper UAC Bypass

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of fodhelper.exe, which is known to exploit a User Account Control (UAC) bypass by leveraging specific registry keys. The detection method uses Endpoint Detection and Response (EDR) telemetry to identify when fodhelper.exe spawns a child process and accesses the registry keys. This activity is significant because it indicates a potential privilege escalation attempt by an attacker. If confirmed malicious, the attacker could execute commands with elevated privileges, leading to unauthorized system changes and potential full system compromise.

## MITRE ATT&CK

- T1112
- T1548.002

## Analytic Stories

- IcedID
- ValleyRAT
- Compromised Windows Host
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/fodhelper_uac_bypass.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
