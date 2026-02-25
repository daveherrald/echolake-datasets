# Disable Show Hidden Files

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting modifications to the Windows registry that disable the display of hidden files. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to registry paths associated with hidden file settings. This activity is significant because malware, such as worms and trojan spyware, often use hidden files to evade detection. If confirmed malicious, this behavior could allow an attacker to conceal malicious files on the system, making it harder for security tools and analysts to identify and remove the threat.

## MITRE ATT&CK

- T1112
- T1562.001
- T1564.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse
- Azorult

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** WinEventLog:Security
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-security.log

- **Source:** WinEventLog:System
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-system.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_show_hidden_files.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
