# Windows Outlook Macro Security Modified

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

The following analytic detects the modification of the Windows Registry key "Level" under Outlook Security. This allows macros to execute without warning, which could allow malicious scripts to run without notice. This detection leverages data from the Endpoint.Registry datamodel, specifically looking for the registry value name "Level" with a value of "0x00000001". This activity is significant as it is commonly associated with some malware infections, indicating potential malicious intent to harvest email information.

## MITRE ATT&CK

- T1137
- T1008

## Analytic Stories

- NotDoor Malware
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/notdoor/macro_security_level/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_outlook_macro_security_modified.yml)*
