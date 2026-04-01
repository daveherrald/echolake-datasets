# Windows Wmic Memory Chip Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of Windows Management Instrumentation Command-line (WMIC) commands related to memory chip discovery on a Windows system. Specifically, it monitors instances where commands such as “wmic memorychip” are used to retrieve detailed information about installed RAM modules. While these commands can serve legitimate administrative and troubleshooting purposes, they may also be employed by adversaries to gather system hardware specifications as part of their reconnaissance activities. By identifying and alerting on WMIC memory chip queries, security teams can enhance their ability to spot unauthorized information gathering and take proactive measures to mitigate potential threats.

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

*Source: [Splunk Security Content](detections/endpoint/windows_wmic_memory_chip_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
