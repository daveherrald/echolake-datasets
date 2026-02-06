# Windows Disable Windows Group Policy Features Through Registry

**Type:** Anomaly

**Author:** Steven Dick, Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious registry modifications aimed at disabling Windows Group Policy features. It leverages data from the Endpoint.Registry data model, focusing on specific registry paths and values associated with disabling key Windows functionalities. This activity is significant because it is commonly used by ransomware to hinder mitigation and forensic response efforts. If confirmed malicious, this behavior could severely impair the ability of security teams to analyze and respond to the attack, allowing the attacker to maintain control and persist within the compromised environment.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Ransomware
- CISA AA23-347A
- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/ransomware_disable_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_windows_group_policy_features_through_registry.yml)*
