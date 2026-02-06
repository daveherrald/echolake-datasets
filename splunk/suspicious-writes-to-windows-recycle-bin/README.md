# Suspicious writes to windows Recycle Bin

**Type:** TTP

**Author:** Rico Valdez, Splunk

## Description

The following analytic detects when a process other than explorer.exe writes to the Windows Recycle Bin. It leverages the Endpoint.Filesystem and Endpoint.Processes data models in Splunk to identify any process writing to the "*$Recycle.Bin*" file path, excluding explorer.exe. This activity is significant because it may indicate an attacker attempting to hide their actions, potentially leading to data theft, ransomware, or other malicious outcomes. If confirmed malicious, this behavior could allow an attacker to persist in the environment and evade detection by security tools.

## MITRE ATT&CK

- T1036

## Analytic Stories

- Collection and Staging
- PlugX

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/write_to_recycle_bin/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_writes_to_windows_recycle_bin.yml)*
