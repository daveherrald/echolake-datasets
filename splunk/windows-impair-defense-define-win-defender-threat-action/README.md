# Windows Impair Defense Define Win Defender Threat Action

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows Defender ThreatSeverityDefaultAction registry setting. It leverages data from the Endpoint.Registry datamodel to identify changes in registry values that define how Windows Defender responds to threats. This activity is significant because altering these settings can impair the system's defense mechanisms, potentially allowing threats to go unaddressed. If confirmed malicious, this could enable attackers to bypass antivirus protections, leading to persistent threats and increased risk of data compromise or further system exploitation.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_define_win_defender_threat_action.yml)*
