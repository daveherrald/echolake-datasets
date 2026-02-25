# Windows Cabinet File Extraction Via Expand

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

Detects usage of expand.exe to extract Microsoft Cabinet (CAB) archives, with
emphasis on extractions into `C:\\ProgramData` or similar staging locations. In
recent APT37 activity, a CAB payload (e.g., wonder.cab) was expanded into
ProgramData prior to persistence and execution. This behavior is a strong signal
for ingress tool transfer and staging of payloads.


## MITRE ATT&CK

- T1105

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1140/atomic_red_team/expand_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_cabinet_file_extraction_via_expand.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
