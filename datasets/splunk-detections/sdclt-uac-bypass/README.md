# Sdclt UAC Bypass

**Type:** TTP

**Author:** Steven Dick, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious modifications to the sdclt.exe registry, a technique often used to bypass User Account Control (UAC). It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific registry paths and values associated with sdclt.exe. This activity is significant because UAC bypasses can allow attackers to execute payloads with elevated privileges without user consent. If confirmed malicious, this could lead to unauthorized code execution, privilege escalation, and potential persistence within the environment, posing a severe security risk.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 12
- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/sdclt_uac_bypass.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
