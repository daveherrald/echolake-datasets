# Windows Screen Capture in TEMP folder

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of screen capture files by the Braodo stealer malware. This stealer is known to capture screenshots of the victim's desktop as part of its data theft activities. The detection focuses on identifying unusual screen capture activity, especially when images are saved in directories often used by malware, such as temporary or hidden folders. Monitoring for these files helps to quickly identify malicious screen capture attempts, allowing security teams to respond and mitigate potential information exposure before sensitive data is compromised.

## MITRE ATT&CK

- T1113

## Analytic Stories

- StealC Stealer
- Crypto Stealer
- Braodo Stealer
- APT37 Rustonotto and FadeStealer
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1113/braodo_screenshot/braodo_screenshot.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_screen_capture_in_temp_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
