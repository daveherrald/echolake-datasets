# Windows Modify Registry NoChangingWallPaper

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry aimed at preventing wallpaper changes. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to the "NoChangingWallPaper" registry value. This activity is significant as it is a known tactic used by Rhysida ransomware to enforce a malicious wallpaper, thereby limiting user control over system settings. If confirmed malicious, this registry change could indicate a ransomware infection, leading to further system compromise and user disruption.

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


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
