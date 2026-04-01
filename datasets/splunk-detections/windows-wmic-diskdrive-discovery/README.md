# Windows Wmic DiskDrive Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of Windows Management Instrumentation Command-line (WMIC) for disk drive discovery activities on a Windows system. This process involves monitoring commands such as “wmic diskdrive” which are often used by administrators for inventory and diagnostics but can also be leveraged by attackers to enumerate hardware details for malicious purposes. Detecting these commands is essential for identifying potentially unauthorized asset reconnaissance or pre-attack mapping behaviors. By capturing and analyzing WMIC disk drive queries, security teams can gain visibility into suspicious activities, enabling them to respond promptly and strengthen the organization’s security posture against insider threats or lateral movement attempts.

## MITRE ATT&CK

- T1082

## Analytic Stories

- LAMEHUG

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/lamehug/T1082/wmic_cmd/wmic_cmd.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wmic_diskdrive_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
