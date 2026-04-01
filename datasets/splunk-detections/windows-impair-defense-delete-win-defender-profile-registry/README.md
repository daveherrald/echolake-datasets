# Windows Impair Defense Delete Win Defender Profile Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the deletion of the Windows Defender main profile registry key. It leverages data from the Endpoint.Registry datamodel, specifically monitoring for deleted actions within the Windows Defender registry path. This activity is significant as it indicates potential tampering with security defenses, often associated with Remote Access Trojans (RATs) and other malware. If confirmed malicious, this action could allow an attacker to disable Windows Defender, reducing the system's ability to detect and respond to further malicious activities, thereby compromising endpoint security.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/delete_win_defender_context_menu/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_delete_win_defender_profile_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
