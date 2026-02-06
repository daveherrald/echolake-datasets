# Windows Indicator Removal Via Rmdir

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the 'rmdir' command with '/s' and '/q' options to delete files and directory trees. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process metadata. This activity is significant as it may indicate malware attempting to remove traces or components during cleanup operations. If confirmed malicious, this behavior could allow attackers to eliminate forensic evidence, hinder incident response efforts, and maintain persistence by removing indicators of compromise.

## MITRE ATT&CK

- T1070

## Analytic Stories

- DarkGate Malware
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070/rmdir_delete_files_and_dir/rmdir.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_indicator_removal_via_rmdir.yml)*
