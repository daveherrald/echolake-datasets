# Detect Renamed WinRAR

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies instances where `WinRAR.exe` has been renamed and executed. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and original file names within the Endpoint data model. This activity is significant because renaming executables is a common tactic used by attackers to evade detection. If confirmed malicious, this could indicate an attempt to bypass security controls, potentially leading to unauthorized data extraction or further system compromise.

## MITRE ATT&CK

- T1560.001

## Analytic Stories

- China-Nexus Threat Activity
- Collection and Staging
- CISA AA22-277A
- Salt Typhoon

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_renamed_winrar.yml)*
