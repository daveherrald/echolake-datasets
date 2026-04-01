# Windows Archived Collected Data In TEMP Folder

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of archived files in a temporary folder, which may contain collected data. This behavior is often associated with malicious activity, where attackers compress sensitive information before exfiltration. The detection focuses on monitoring specific directories, such as temp folders, for the presence of newly created archive files (e.g., .zip, .rar, .tar). By identifying this pattern, security teams can quickly respond to potential data collection and exfiltration attempts, minimizing the risk of data breaches and improving overall threat detection.

## MITRE ATT&CK

- T1560

## Analytic Stories

- Braodo Stealer
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560/archived_in_temp_dir/braodo_zip_temp.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_archived_collected_data_in_temp_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
