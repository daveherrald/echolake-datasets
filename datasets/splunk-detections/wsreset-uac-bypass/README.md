# WSReset UAC Bypass

**Type:** TTP

**Author:** Steven Dick, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious modification of the registry aimed at bypassing User Account Control (UAC) by leveraging WSReset.exe. It identifies the creation or modification of specific registry values under the path "*\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command*". This detection uses data from Endpoint Detection and Response (EDR) agents, focusing on process and registry events. This activity is significant because UAC bypass techniques can allow attackers to execute high-privilege actions without user consent. If confirmed malicious, this could lead to unauthorized code execution and potential system compromise.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Windows Defense Evasion Tactics
- Living Off The Land
- Windows Registry Abuse
- MoonPeak

## Data Sources

- Sysmon EventID 12
- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/wsreset_uac_bypass.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
