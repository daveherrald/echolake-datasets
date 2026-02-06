# Anomalous usage of 7zip

**Type:** Anomaly

**Author:** Michael Haag, Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of 7z.exe, a 7-Zip utility, spawned from rundll32.exe or dllhost.exe. This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on process names and parent processes. This activity is significant as it may indicate an adversary attempting to use 7-Zip for data exfiltration, often by renaming the executable to evade detection. If confirmed malicious, this could lead to unauthorized data archiving and exfiltration, compromising sensitive information and potentially leading to further system exploitation.

## MITRE ATT&CK

- T1560.001

## Analytic Stories

- NOBELIUM Group
- BlackByte Ransomware
- Cobalt Strike
- Graceful Wipe Out Attack
- BlackSuit Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/anomalous_usage_of_7zip.yml)*
