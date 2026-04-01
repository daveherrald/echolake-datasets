# Windows Modify Registry Suppress Win Defender Notif

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications in the Windows registry to suppress Windows Defender notifications. It leverages data from the Endpoint.Registry datamodel, specifically targeting changes to the "Notification_Suppress" registry value. This activity is significant because adversaries, including those deploying Azorult malware, use this technique to bypass Windows Defender and disable critical notifications. If confirmed malicious, this behavior could allow attackers to evade detection, maintain persistence, and execute further malicious activities without alerting the user or security tools.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Azorult
- CISA AA23-347A

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_suppress_win_defender_notif.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
