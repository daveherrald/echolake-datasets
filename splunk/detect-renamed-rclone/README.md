# Detect Renamed RClone

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of a renamed `rclone.exe` process, which is commonly used for data exfiltration to remote destinations. This detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process names and original file names that do not match. This activity is significant because ransomware groups often use RClone to exfiltrate sensitive data. If confirmed malicious, this behavior could indicate an ongoing data exfiltration attempt, potentially leading to significant data loss and further compromise of the affected systems.

## MITRE ATT&CK

- T1020

## Analytic Stories

- DarkSide Ransomware
- Ransomware
- Black Basta Ransomware
- Cactus Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1020/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_renamed_rclone.yml)*
