# Windows Powershell Import Applocker Policy

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the import of Windows PowerShell Applocker cmdlets, specifically identifying the use of "Import-Module Applocker" and "Set-AppLockerPolicy" with an XML policy. It leverages PowerShell Script Block Logging (EventCode 4104) to capture and analyze script block text. This activity is significant as it may indicate an attempt to enforce restrictive Applocker policies, potentially used by malware like Azorult to disable antivirus products. If confirmed malicious, this could allow an attacker to bypass security controls, leading to further system compromise and persistence.

## MITRE ATT&CK

- T1059.001
- T1562.001

## Analytic Stories

- Azorult

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/import_applocker_policy/windows-powershell-xml2.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_import_applocker_policy.yml)*
