# Windows Replication Through Removable Media

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation or dropping of executable or script files in the root directory of a removable drive. It leverages data from the Endpoint.Filesystem datamodel, focusing on specific file types and their creation paths. This activity is significant as it may indicate an attempt to spread malware, such as ransomware, via removable media. If confirmed malicious, this behavior could lead to unauthorized code execution, lateral movement, or persistence within the network, potentially compromising sensitive data and systems.

## MITRE ATT&CK

- T1091

## Analytic Stories

- PlugX
- China-Nexus Threat Activity
- Chaos Ransomware
- Derusbi
- Salt Typhoon
- NjRAT
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/chaos_ransomware/spread_in_root_drives/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_replication_through_removable_media.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
