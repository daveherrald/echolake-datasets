# Windows High File Deletion Frequency

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic identifies a high frequency of file deletions by monitoring Sysmon EventCodes 23 and 26 for specific file extensions. This detection leverages Sysmon logs to track deleted target filenames, process names, and process IDs. Such activity is significant as it often indicates ransomware behavior, where files are encrypted and the originals are deleted. If confirmed malicious, this activity could lead to extensive data loss and operational disruption, as ransomware can render critical files inaccessible, demanding a ransom for their recovery.

## MITRE ATT&CK

- T1485

## Analytic Stories

- Sandworm Tools
- Handala Wiper
- Data Destruction
- WhisperGate
- Swift Slicer
- Medusa Ransomware
- DarkCrystal RAT
- Black Basta Ransomware
- Clop Ransomware
- Interlock Ransomware
- NailaoLocker Ransomware
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 23
- Sysmon EventID 26

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_high_file_deletion_frequency.yml)*
