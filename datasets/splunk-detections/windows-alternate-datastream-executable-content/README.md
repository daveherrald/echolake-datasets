# Windows Alternate DataStream - Executable Content

**Type:** TTP

**Author:** Steven Dick, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the writing of data with an IMPHASH value to an Alternate Data Stream (ADS) in the NTFS file system. It leverages Sysmon Event ID 15 and regex to identify files with a Portable Executable (PE) structure. This activity is significant as it may indicate a threat actor staging malicious code in hidden areas for persistence or future execution. If confirmed malicious, this could allow attackers to execute hidden code, maintain persistence, or escalate privileges within the environment.

## MITRE ATT&CK

- T1564.004

## Analytic Stories

- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 15

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1564.004/ads_abuse/ads_abuse_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_alternate_datastream___executable_content.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
