# Windows Modify Registry NoChangingWallPaper

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry aimed at preventing wallpaper changes. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to the "NoChangingWallPaper" registry value. This activity is significant as it is a known tactic used by Rhysida ransomware to enforce a malicious wallpaper, thereby limiting user control over system settings. If confirmed malicious, this registry change could indicate a ransomware infection, leading to further system compromise and user disruption.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Rhysida Ransomware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/no_changing_wallpaper/NoChangingWallPaper.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_nochangingwallpaper.yml)*
