# Detect Outlook exe writing a zip file

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying the execution of `outlook.exe` writing a `.zip` file to the disk.
It leverages data from the Endpoint data model, specifically monitoring process and filesystem activities.
This behavior can be significant as it may indicate the use of Outlook to deliver malicious payloads or exfiltrate data via compressed files.
If confirmed malicious, this activity could lead to unauthorized data access, data exfiltration, or the delivery of malware, potentially compromising the security of the affected system and network.


## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Amadey
- APT37 Rustonotto and FadeStealer
- Meduza Stealer
- PXA Stealer
- Remcos
- Spearphishing Attachments

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/outlook_writing_zip/outlook_writing_zip.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_outlook_exe_writing_a_zip_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
