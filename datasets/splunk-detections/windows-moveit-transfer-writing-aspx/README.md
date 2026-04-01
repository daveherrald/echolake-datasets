# Windows MOVEit Transfer Writing ASPX

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the creation of new ASPX files in the MOVEit Transfer application's "wwwroot" directory. It leverages endpoint data on process and filesystem activity to identify processes responsible for creating these files. This activity is significant as it may indicate exploitation of a critical zero-day vulnerability in MOVEit Transfer, used by threat actors to install malicious ASPX files. If confirmed malicious, this could lead to exfiltration of sensitive data, including user credentials and file metadata, posing a severe risk to the organization's security.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- MOVEit Transfer Critical Vulnerability
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/moveit_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_moveit_transfer_writing_aspx.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
