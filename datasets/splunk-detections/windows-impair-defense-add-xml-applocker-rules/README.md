# Windows Impair Defense Add Xml Applocker Rules

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of a PowerShell commandlet to import an AppLocker XML policy. This behavior is identified by monitoring processes that execute the "Import-Module Applocker" and "Set-AppLockerPolicy" commands with the "-XMLPolicy" parameter. This activity is significant because it can indicate an attempt to disable or bypass security controls, as seen in the Azorult malware. If confirmed malicious, this could allow an attacker to disable antivirus products, leading to further compromise and persistence within the environment.

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


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
