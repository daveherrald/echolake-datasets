# Windows Vulnerable Driver Loaded

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the loading of known vulnerable Windows drivers, which may indicate potential persistence or privilege escalation attempts. It leverages Sysmon EventCode 6 to identify driver loading events and cross-references them with a list of vulnerable drivers. This activity is significant as attackers often exploit vulnerable drivers to gain elevated privileges or maintain persistence on a system. If confirmed malicious, this could allow attackers to execute arbitrary code with high privileges, leading to further system compromise and potential data exfiltration.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- Windows Drivers
- BlackByte Ransomware

## Data Sources

- Sysmon EventID 6

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1014/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_vulnerable_driver_loaded.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
