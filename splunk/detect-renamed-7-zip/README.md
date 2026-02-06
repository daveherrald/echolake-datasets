# Detect Renamed 7-Zip

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the usage of a renamed 7-Zip executable using Sysmon data. It leverages the OriginalFileName field to identify instances where the 7-Zip process has been renamed. This activity is significant as attackers often rename legitimate tools to evade detection while staging or exfiltrating data. If confirmed malicious, this behavior could indicate data exfiltration attempts or other unauthorized data manipulation, potentially leading to significant data breaches or loss of sensitive information. Analysts should validate the legitimacy of the 7-Zip executable and investigate parallel processes for further suspicious activities.

## MITRE ATT&CK

- T1560.001

## Analytic Stories

- Collection and Staging
- Malicious Inno Setup Loader

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_renamed_7_zip.yml)*
