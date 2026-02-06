# Windows WMIC Shadowcopy Delete

**Type:** Anomaly

**Author:** Michael Haag, AJ King, Splunk

## Description

This analytic detects the use of WMIC to delete volume shadow copies, which is a common technique used by ransomware actors to prevent system recovery. Ransomware like Cactus often delete shadow copies before encrypting files to ensure victims cannot recover their data without paying the ransom. This behavior is particularly concerning as it indicates potential ransomware activity or malicious actors attempting to prevent system recovery.

## MITRE ATT&CK

- T1490

## Analytic Stories

- Cactus Ransomware
- Volt Typhoon
- Suspicious WMI Use

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/shadowcopy_del/wmicshadowcopydelete_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wmic_shadowcopy_delete.yml)*
