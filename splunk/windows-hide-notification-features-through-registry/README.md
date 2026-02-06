# Windows Hide Notification Features Through Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects suspicious registry modifications aimed at hiding common Windows notification features on a compromised host. It leverages data from the Endpoint.Registry data model, focusing on specific registry paths and values. This activity is significant as it is often used by ransomware to obscure visual indicators, increasing the impact of the attack. If confirmed malicious, this could prevent users from noticing critical system alerts, thereby aiding the attacker in maintaining persistence and furthering their malicious activities undetected.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Ransomware
- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/ransomware_disable_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_hide_notification_features_through_registry.yml)*
