# Windows Modify Registry Suppress Win Defender Notif

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications in the Windows registry to suppress Windows Defender notifications. It leverages data from the Endpoint.Registry datamodel, specifically targeting changes to the "Notification_Suppress" registry value. This activity is significant because adversaries, including those deploying Azorult malware, use this technique to bypass Windows Defender and disable critical notifications. If confirmed malicious, this behavior could allow attackers to evade detection, maintain persistence, and execute further malicious activities without alerting the user or security tools.

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
