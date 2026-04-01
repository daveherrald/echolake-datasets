# Common Ransomware Extensions

**Type:** TTP

**Author:** David Dorsey, Michael Haag, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting modifications to files with extensions commonly associated with ransomware. It leverages the Endpoint.Filesystem data model to identify changes in file extensions that match known ransomware patterns. This activity is significant because it suggests an attacker is attempting to encrypt or alter files, potentially leading to severe data loss and operational disruption. If confirmed malicious, this activity could result in the encryption of critical data, rendering it inaccessible and causing significant damage to the organization's data integrity and availability.

## MITRE ATT&CK

- T1485

## Analytic Stories

- Rhysida Ransomware
- Prestige Ransomware
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

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/ransomware_notes/ransom-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/common_ransomware_extensions.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
