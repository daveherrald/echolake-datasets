# Windows Rundll32 Apply User Settings Changes

**Type:** Anomaly

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the execution of rundll32 with a call to the user32 DLL, specifically the UpdatePerUserSystemParameters function.
This function is responsible for updating system parameters, such as desktop backgrounds, display settings, and visual themes. 
It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions.
This activity can be significant as it is an uncommon way to apply settings. It was also observed as part of Rhysida Ransomware activity. 
If confirmed malicious, this could allow an attacker to disguise activities or make unauthorized system changes, potentially leading to persistent unauthorized access.


## MITRE ATT&CK

- T1218.011

## Analytic Stories

- Rhysida Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/update_per_user_system/rundll32_updateperusersystem.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rundll32_apply_user_settings_changes.yml)*
