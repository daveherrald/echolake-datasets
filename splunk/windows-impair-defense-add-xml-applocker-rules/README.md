# Windows Impair Defense Add Xml Applocker Rules

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of a PowerShell commandlet to import an AppLocker XML policy. This behavior is identified by monitoring processes that execute the "Import-Module Applocker" and "Set-AppLockerPolicy" commands with the "-XMLPolicy" parameter. This activity is significant because it can indicate an attempt to disable or bypass security controls, as seen in the Azorult malware. If confirmed malicious, this could allow an attacker to disable antivirus products, leading to further compromise and persistence within the environment.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Azorult

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_add_xml_applocker_rules.yml)*
