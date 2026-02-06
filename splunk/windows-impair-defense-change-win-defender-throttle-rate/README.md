# Windows Impair Defense Change Win Defender Throttle Rate

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the ThrottleDetectionEventsRate registry setting in Windows Defender. It leverages data from the Endpoint.Registry datamodel to identify changes in the registry path related to Windows Defender's event logging rate. This activity is significant because altering the ThrottleDetectionEventsRate can reduce the frequency of logged detection events, potentially masking malicious activities. If confirmed malicious, this could allow an attacker to evade detection by decreasing the visibility of security events, thereby hindering incident response and forensic investigations.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_change_win_defender_throttle_rate.yml)*
