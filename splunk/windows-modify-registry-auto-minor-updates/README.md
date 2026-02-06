# Windows Modify Registry Auto Minor Updates

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies a suspicious modification to the Windows auto update configuration registry. It detects changes to the registry path "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\AutoInstallMinorUpdates" with a value of "0x00000000". This activity is significant as it is commonly used by adversaries, including malware like RedLine Stealer, to bypass detection and deploy additional payloads. If confirmed malicious, this modification could allow attackers to evade defenses, potentially leading to further system compromise and exploitation of zero-day vulnerabilities.

## MITRE ATT&CK

- T1112

## Analytic Stories

- RedLine Stealer

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/modify_registry/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_auto_minor_updates.yml)*
