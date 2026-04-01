# Windows Outlook LoadMacroProviderOnBoot Persistence

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This dataset contains sample data for detecting the modification of the Windows Registry key "LoadMacroProviderOnBoot" under Outlook. This enables automatic loading of macros, which could allow malicious scripts to run without notice. This detection leverages data from the Endpoint.Registry datamodel to search for this key being enabled. This activity is significant as it is commonly associated with some malware infections, indicating potential malicious intent to harvest email information.

## MITRE ATT&CK

- T1112
- T1137

## Analytic Stories

- NotDoor Malware
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/notdoor/loadmacroprovideronboot/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_outlook_loadmacroprovideronboot_persistence.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
