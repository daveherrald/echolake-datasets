# Windows Modify Registry No Auto Update

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies a suspicious modification to the Windows registry that disables automatic updates. It detects changes to the registry path `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate` with a value of `0x00000001`. This activity is significant as it is commonly used by adversaries, including malware like RedLine Stealer, to evade detection and maintain persistence. If confirmed malicious, this could allow attackers to bypass security updates, leaving the system vulnerable to further exploitation and potential zero-day attacks.

## MITRE ATT&CK

- T1112

## Analytic Stories

- CISA AA23-347A
- RedLine Stealer

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/modify_registry/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_no_auto_update.yml)*
