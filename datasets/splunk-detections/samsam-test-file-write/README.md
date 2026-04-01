# Samsam Test File Write

**Type:** TTP

**Author:** Rico Valdez, Splunk

## Description

This dataset contains sample data for detecting the creation of a file named "test.txt" within the Windows system directory, indicative of Samsam ransomware propagation. It leverages file-system activity data from the Endpoint data model, specifically monitoring file paths within the Windows System32 directory. This activity is significant as it aligns with known Samsam ransomware behavior, which uses such files for propagation and execution. If confirmed malicious, this could lead to ransomware deployment, resulting in data encryption, system disruption, and potential data loss. Immediate investigation and remediation are crucial to prevent further damage.

## MITRE ATT&CK

- T1486

## Analytic Stories

- SamSam Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/sam_sam_note/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/samsam_test_file_write.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
