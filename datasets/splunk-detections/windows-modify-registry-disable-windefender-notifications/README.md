# Windows Modify Registry Disable WinDefender Notifications

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious registry modification aimed at disabling Windows Defender notifications. It leverages data from the Endpoint.Registry data model, specifically looking for changes to the registry path "*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications\\DisableNotifications" with a value of "0x00000001". This activity is significant as it indicates an attempt to evade detection by disabling security alerts, a technique used by adversaries and malware like RedLine Stealer. If confirmed malicious, this could allow attackers to operate undetected, increasing the risk of further compromise and data exfiltration.

## MITRE ATT&CK

- T1112

## Analytic Stories

- CISA AA23-347A
- RedLine Stealer

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/modify_registry/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_disable_windefender_notifications.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
