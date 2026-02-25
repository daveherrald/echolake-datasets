# Windows Raw Access To Master Boot Record Drive

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious raw access reads to the drive containing the Master Boot Record (MBR). It leverages Sysmon EventCode 9 to identify processes attempting to read or write to the MBR sector, excluding legitimate system processes. This activity is significant because adversaries often target the MBR to wipe, encrypt, or overwrite it as part of their impact payload. If confirmed malicious, this could lead to system instability, data loss, or a complete system compromise, severely impacting the organization's operations.

## MITRE ATT&CK

- T1561.002

## Analytic Stories

- CISA AA22-264A
- WhisperGate
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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1561.002/mbr_raw_access/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_raw_access_to_master_boot_record_drive.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
