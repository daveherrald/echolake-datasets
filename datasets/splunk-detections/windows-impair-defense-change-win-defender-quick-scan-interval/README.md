# Windows Impair Defense Change Win Defender Quick Scan Interval

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry that change the Windows Defender Quick Scan Interval. It leverages data from the Endpoint.Registry data model, focusing on changes to the "QuickScanInterval" registry path. This activity is significant because altering the scan interval can impair Windows Defender's ability to detect malware promptly, potentially allowing threats to persist undetected. If confirmed malicious, this modification could enable attackers to bypass security measures, maintain persistence, and execute further malicious activities without being detected by quick scans.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable-windows-security-defender-features/windefender-bypas-2-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_change_win_defender_quick_scan_interval.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
