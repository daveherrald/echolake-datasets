# Common Ransomware Notes

**Type:** Hunting

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for detecting the creation of files with names commonly associated with ransomware notes.
It leverages file-system activity data from the Endpoint Filesystem data model, typically populated by endpoint detection and response (EDR) tools or Sysmon logs.
This activity is significant because ransomware notes indicate a potential ransomware attack, which can lead to data encryption and extortion.
If confirmed malicious, this activity could result in significant data loss, operational disruption, and financial impact due to ransom demands.
Note that this analytic relies on a lookup table (ransomware_notes_lookup) that contains known ransomware note file names.
Ensure that this lookup table is regularly updated to include new ransomware note file names as they are identified in the threat landscape.
Also this analytic leverages a sub-search to enhance performance. sub-searches have limitations on the amount of data they can return. Keep this in mind if you have an extensive list of ransomware note file names.


## MITRE ATT&CK

- T1485

## Analytic Stories

- Chaos Ransomware
- Rhysida Ransomware
- Ransomware
- LockBit Ransomware
- Medusa Ransomware
- SamSam Ransomware
- Clop Ransomware
- Ryuk Ransomware
- Black Basta Ransomware
- Termite Ransomware
- Interlock Ransomware
- NailaoLocker Ransomware
- Hellcat Ransomware
- Storm-0501 Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/ransomware_notes/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/common_ransomware_notes.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
