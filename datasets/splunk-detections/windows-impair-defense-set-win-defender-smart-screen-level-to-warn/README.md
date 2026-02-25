# Windows Impair Defense Set Win Defender Smart Screen Level To Warn

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry that set the Windows Defender SmartScreen level to "warn." This detection leverages data from the Endpoint.Registry data model, specifically monitoring changes to the ShellSmartScreenLevel registry value. This activity is significant because altering SmartScreen settings to "warn" can reduce immediate suspicion from users, allowing potentially malicious executables to run with just a warning prompt. If confirmed malicious, this could enable attackers to execute harmful files, increasing the risk of successful malware deployment and subsequent system compromise.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_set_win_defender_smart_screen_level_to_warn.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
