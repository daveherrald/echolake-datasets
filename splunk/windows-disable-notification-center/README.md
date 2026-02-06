# Windows Disable Notification Center

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects the modification of the Windows registry to disable the Notification Center on a host machine. It leverages data from the Endpoint.Registry data model, specifically looking for changes to the "DisableNotificationCenter" registry value set to "0x00000001." This activity is significant because disabling the Notification Center can be a tactic used by RAT malware to hide its presence and subsequent actions. If confirmed malicious, this could allow an attacker to operate stealthily, potentially leading to further system compromise and data exfiltration.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Windows Defense Evasion Tactics
- CISA AA23-347A
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/disable_notif_center/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_notification_center.yml)*
