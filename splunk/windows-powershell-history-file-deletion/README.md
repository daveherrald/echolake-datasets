# Windows Powershell History File Deletion

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the usage of PowerShell to delete its command history file, which may indicate an attempt to evade detection by removing evidence of executed commands. PowerShell stores command history in ConsoleHost_history.txt under the user’s profile directory. Adversaries or malicious scripts may delete this file using Remove-Item, del, or similar commands. This detection focuses on file deletion events targeting the history file, correlating them with recent PowerShell activity. While legitimate users may occasionally clear history, frequent or automated deletions should be investigated for potential defense evasion or post-exploitation cleanup activities.

## MITRE ATT&CK

- T1059.003
- T1070.003

## Analytic Stories

- Medusa Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.003/ConsoleHost_History_deletion/HistorySavePath_powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_history_file_deletion.yml)*
