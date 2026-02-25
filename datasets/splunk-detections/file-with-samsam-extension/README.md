# File with Samsam Extension

**Type:** TTP

**Author:** Rico Valdez, Splunk

## Description

This dataset contains sample data for detecting file writes with extensions indicative of a SamSam ransomware attack.
It leverages file-system activity data to identify file names ending in .stubbin, .berkshire, .satoshi, .sophos, or .keyxml.
This activity is significant because SamSam ransomware is highly destructive, leading to file encryption and ransom demands.
If confirmed malicious, the impact includes significant financial losses, operational disruptions, and reputational damage.
Immediate actions should include isolating affected systems, restoring files from backups, and investigating the attack source to prevent further incidents.


## Analytic Stories

- SamSam Ransomware
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/samsam_extension/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/file_with_samsam_extension.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
