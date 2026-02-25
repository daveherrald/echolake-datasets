# Windows Outlook Dialogs Disabled from Unusual Process

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This dataset contains sample data for detecting the modification of the Windows Registry key "PONT_STRING" under Outlook Options. This disables certain dialog popups, which could allow malicious scripts to run without notice. This detection leverages data from the Endpoint.Registry datamodel to search for this key changing from an unusual process. This activity is significant as it is commonly associated with some malware infections, indicating potential malicious intent to harvest email information.

## MITRE ATT&CK

- T1112
- T1562

## Analytic Stories

- NotDoor Malware
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/notdoor/disable_dialogs/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_outlook_dialogs_disabled_from_unusual_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
