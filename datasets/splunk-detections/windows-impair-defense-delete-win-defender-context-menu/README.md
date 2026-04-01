# Windows Impair Defense Delete Win Defender Context Menu

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the deletion of the Windows Defender context menu entry from the registry. It leverages data from the Endpoint datamodel, specifically monitoring registry actions where the path includes "*\\shellex\\ContextMenuHandlers\\EPP" and the action is 'deleted'. This activity is significant as it is commonly associated with Remote Access Trojan (RAT) malware attempting to disable security features. If confirmed malicious, this could allow an attacker to impair defenses, facilitating further malicious activities such as unauthorized access, persistence, and data exfiltration.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_delete_win_defender_context_menu.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
