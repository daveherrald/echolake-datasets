# Windows Impair Defense Change Win Defender Tracing Level

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry specifically targeting the "WppTracingLevel" setting within Windows Defender. This detection leverages data from the Endpoint.Registry data model to identify changes in the registry path associated with Windows Defender tracing levels. Such modifications are significant as they can impair the diagnostic capabilities of Windows Defender, potentially hiding malicious activities. If confirmed malicious, this activity could allow an attacker to evade detection and maintain persistence within the environment, leading to further compromise and data exfiltration.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_change_win_defender_tracing_level.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
