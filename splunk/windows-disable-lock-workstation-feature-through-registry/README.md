# Windows Disable Lock Workstation Feature Through Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects a suspicious registry modification that disables the Lock Computer feature in Windows. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableLockWorkstation" with a value of "0x00000001". This activity is significant because it prevents users from locking their screens, a tactic often used by malware, including ransomware, to maintain control over compromised systems. If confirmed malicious, this could allow attackers to sustain their presence and execute further malicious actions without user interruption.

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

*Source: [Splunk Security Content](detections/endpoint/windows_disable_lock_workstation_feature_through_registry.yml)*
