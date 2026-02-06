# Windows ClipBoard Data via Get-ClipBoard

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the PowerShell command 'Get-Clipboard' to retrieve clipboard data. It leverages PowerShell Script Block Logging (EventCode 4104) to identify instances where this command is used. This activity is significant because it can indicate an attempt to steal sensitive information such as usernames, passwords, or other confidential data copied to the clipboard. If confirmed malicious, this behavior could lead to unauthorized access to sensitive information, potentially compromising user accounts and other critical assets.

## MITRE ATT&CK

- T1115

## Analytic Stories

- Windows Post-Exploitation
- Prestige Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/powershell/windows-powershell-xml2.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_clipboard_data_via_get_clipboard.yml)*
