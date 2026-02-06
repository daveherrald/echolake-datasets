# Windows Impair Defenses Disable Win Defender Auto Logging

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the disabling of Windows Defender logging by identifying changes to the Registry keys DefenderApiLogger or DefenderAuditLogger set to disable. It leverages data from the Endpoint.Registry datamodel to monitor specific registry paths and values. This activity is significant as it is commonly associated with Remote Access Trojan (RAT) malware attempting to evade detection. If confirmed malicious, this action could allow an attacker to conceal their activities, making it harder to detect further malicious actions and maintain persistence on the compromised endpoint.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- CISA AA23-347A
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable_defender_logging/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defenses_disable_win_defender_auto_logging.yml)*
