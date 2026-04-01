# Ransomware Notes bulk creation

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the bulk creation of ransomware notes (e.g., .txt, .html, .hta files) on an infected machine. It leverages Sysmon EventCode 11 to detect multiple instances of these file types being created within a short time frame. This activity is significant as it often indicates an active ransomware attack, where the attacker is notifying the victim of the encryption. If confirmed malicious, this behavior could lead to widespread data encryption, rendering critical files inaccessible and potentially causing significant operational disruption.

## MITRE ATT&CK

- T1486

## Analytic Stories

- BlackMatter Ransomware
- DarkSide Ransomware
- Chaos Ransomware
- Rhysida Ransomware
- LockBit Ransomware
- Medusa Ransomware
- Black Basta Ransomware
- Clop Ransomware
- Cactus Ransomware
- Termite Ransomware
- Interlock Ransomware
- NailaoLocker Ransomware
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/ransomware_notes_bulk_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
