# Remcos RAT File Creation in Remcos Folder

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Sanjay Govind

## Description

This dataset contains sample data for detecting the creation of files in the Remcos folder within the AppData directory, specifically targeting keylog and clipboard log files. It leverages the Endpoint.Filesystem data model to identify .dat files created in paths containing "remcos." This activity is significant as it indicates the presence of the Remcos RAT, which performs keylogging, clipboard capturing, and audio recording. If confirmed malicious, this could lead to unauthorized data exfiltration and extensive surveillance capabilities for the attacker.

## MITRE ATT&CK

- T1113

## Analytic Stories

- Remcos

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_agent/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/remcos_rat_file_creation_in_remcos_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
