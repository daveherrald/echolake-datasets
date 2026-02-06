# Windows Modify Show Compress Color And Info Tip Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects suspicious modifications to the Windows registry keys related to file compression color and information tips. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the "ShowCompColor" and "ShowInfoTip" values under the "Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" path. This activity is significant as it was observed in the Hermetic Wiper malware, indicating potential malicious intent to alter file attributes and user interface elements. If confirmed malicious, this could signify an attempt to manipulate file visibility and deceive users, potentially aiding in further malicious activities.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Data Destruction
- Windows Defense Evasion Tactics
- Windows Registry Abuse
- Hermetic Wiper

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/hermetic_wiper/globalfolderoptions_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_show_compress_color_and_info_tip_registry.yml)*
