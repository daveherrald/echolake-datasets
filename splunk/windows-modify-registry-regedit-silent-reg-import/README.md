# Windows Modify Registry Regedit Silent Reg Import

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the modification of the Windows registry using the regedit.exe application with the silent mode parameter. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because the silent mode allows registry changes without user confirmation, which can be exploited by adversaries to import malicious registry settings. If confirmed malicious, this could enable attackers to persist in the environment, escalate privileges, or manipulate system configurations, leading to potential system compromise.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Azorult

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_regedit_silent_reg_import.yml)*
