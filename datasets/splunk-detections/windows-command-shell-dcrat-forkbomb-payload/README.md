# Windows Command Shell DCRat ForkBomb Payload

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of a DCRat "forkbomb" payload, which spawns multiple cmd.exe processes that launch notepad.exe instances in quick succession. This detection leverages Endpoint Detection and Response (EDR) data, focusing on the rapid creation of cmd.exe and notepad.exe processes within a 30-second window. This activity is significant as it indicates a potential DCRat infection, a known Remote Access Trojan (RAT) with destructive capabilities. If confirmed malicious, this behavior could lead to system instability, resource exhaustion, and potential disruption of services.

## MITRE ATT&CK

- T1059.003

## Analytic Stories

- Compromised Windows Host
- DarkCrystal RAT

## Data Sources

- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/dcrat_forkbomb/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_command_shell_dcrat_forkbomb_payload.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
