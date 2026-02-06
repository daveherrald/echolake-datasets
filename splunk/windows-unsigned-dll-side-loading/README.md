# Windows Unsigned DLL Side-Loading

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of potentially malicious unsigned DLLs in the c:\windows\system32 or c:\windows\syswow64 folders. It leverages Sysmon EventCode 7 logs to identify unsigned DLLs with unavailable signatures loaded in these critical directories. This activity is significant as it may indicate a DLL hijacking attempt, a technique used by attackers to gain unauthorized access and execute malicious code. If confirmed malicious, this could lead to privilege escalation, allowing the attacker to gain elevated privileges and further compromise the target system.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- China-Nexus Threat Activity
- Derusbi
- Warzone RAT
- Salt Typhoon
- NjRAT
- Earth Alux

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/warzone_rat/unsigned_dll_loaded/loaded_unsigned_dll.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unsigned_dll_side_loading.yml)*
