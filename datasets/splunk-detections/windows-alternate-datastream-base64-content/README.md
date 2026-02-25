# Windows Alternate DataStream - Base64 Content

**Type:** TTP

**Author:** Steven Dick, Teoderick Contreras, Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the creation of Alternate Data Streams (ADS) with Base64 content on Windows systems. It leverages Sysmon EventID 15, which captures file creation events, including the content of named streams. ADS can conceal malicious payloads, making them significant for SOC monitoring. This detection identifies hidden streams that may contain executables, scripts, or configuration data, often used by malware to evade detection. If confirmed malicious, this activity could allow attackers to hide and execute payloads, persist in the environment, or access sensitive information without being easily detected.

## MITRE ATT&CK

- T1564.004

## Analytic Stories

- Windows Defense Evasion Tactics
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 15

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1564.004/ads_abuse/ads_abuse_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_alternate_datastream___base64_content.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
