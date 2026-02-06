# Delete ShadowCopy With PowerShell

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of PowerShell to delete shadow copies via the WMIC PowerShell module. It leverages EventCode 4104 and searches for specific keywords like "ShadowCopy," "Delete," or "Remove" within the ScriptBlockText. This activity is significant because deleting shadow copies is a common tactic used by ransomware, such as DarkSide, to prevent data recovery. If confirmed malicious, this action could lead to irreversible data loss and hinder recovery efforts, significantly impacting business continuity and data integrity.

## MITRE ATT&CK

- T1490

## Analytic Stories

- DarkSide Ransomware
- Ransomware
- Revil Ransomware
- DarkGate Malware
- Cactus Ransomware
- VanHelsing Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/single_event_delete_shadowcopy.log


---

*Source: [Splunk Security Content](detections/endpoint/delete_shadowcopy_with_powershell.yml)*
