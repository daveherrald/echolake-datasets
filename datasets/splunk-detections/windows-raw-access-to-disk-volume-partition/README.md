# Windows Raw Access To Disk Volume Partition

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious raw access reads to the device disk partition of a host machine. It leverages Sysmon EventCode 9 logs to identify processes attempting to read or write to the boot sector, excluding legitimate system processes. This activity is significant as it is commonly associated with destructive actions by adversaries, such as wiping, encrypting, or overwriting the boot sector, as seen in attacks involving malware like HermeticWiper. If confirmed malicious, this behavior could lead to severe impacts, including system inoperability, data loss, or compromised boot integrity.

## MITRE ATT&CK

- T1561.002

## Analytic Stories

- CISA AA22-264A
- Graceful Wipe Out Attack
- Data Destruction
- Hermetic Wiper
- Caddy Wiper
- BlackByte Ransomware
- NjRAT
- Disk Wiper
- PathWiper

## Data Sources

- Sysmon EventID 9

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/hermetic_wiper/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_raw_access_to_disk_volume_partition.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
