# Windows Disable Change Password Through Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting a suspicious registry modification that disables the Change Password feature on a Windows host. It identifies changes to the registry path "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableChangePassword" with a value of "0x00000001". This activity is significant as it can prevent users from changing their passwords, a tactic often used by ransomware to maintain control over compromised systems. If confirmed malicious, this could hinder user response to an attack, allowing the attacker to persist and potentially escalate their access within the network.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Ransomware
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/ransomware_disable_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_change_password_through_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
