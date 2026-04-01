# Suspicious Image Creation In Appdata Folder

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of image files in the AppData folder by processes that also have a file reference in the same folder. It leverages data from the Endpoint.Processes and Endpoint.Filesystem datamodels to identify this behavior. This activity is significant because it is commonly associated with malware, such as the Remcos RAT, which captures screenshots and stores them in the AppData folder before exfiltrating them to a command-and-control server. If confirmed malicious, this activity could indicate unauthorized data capture and exfiltration, compromising sensitive information and user privacy.

## MITRE ATT&CK

- T1113

## Analytic Stories

- Remcos
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_agent/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_image_creation_in_appdata_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
