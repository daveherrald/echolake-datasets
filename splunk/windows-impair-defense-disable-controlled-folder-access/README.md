# Windows Impair Defense Disable Controlled Folder Access

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a modification in the Windows registry that disables the Windows Defender Controlled Folder Access feature. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the EnableControlledFolderAccess registry setting. This activity is significant because Controlled Folder Access is designed to protect critical folders from unauthorized access, including ransomware attacks. If this activity is confirmed malicious, it could allow attackers to bypass a key security feature, potentially leading to unauthorized access or modification of sensitive files.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable-windows-security-defender-features/windefender-bypas-2-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_controlled_folder_access.yml)*
