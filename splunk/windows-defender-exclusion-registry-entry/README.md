# Windows Defender Exclusion Registry Entry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects modifications to the Windows Defender exclusion registry entries. It leverages endpoint registry data to identify changes in the registry path "*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\*". This activity is significant because adversaries often modify these entries to bypass Windows Defender, allowing malicious code to execute without detection. If confirmed malicious, this behavior could enable attackers to evade antivirus defenses, maintain persistence, and execute further malicious activities undetected.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Qakbot
- Remcos
- ValleyRAT
- XWorm
- Azorult
- Warzone RAT
- Windows Defense Evasion Tactics
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/defender_exclusion_sysmon/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_defender_exclusion_registry_entry.yml)*
