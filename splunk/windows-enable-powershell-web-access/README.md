# Windows Enable PowerShell Web Access

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the enabling of PowerShell Web Access via PowerShell commands. It leverages PowerShell script block logging (EventCode 4104) to identify the execution of the `Install-WindowsFeature` cmdlet with the `WindowsPowerShellWebAccess` parameter. This activity is significant because enabling PowerShell Web Access can facilitate remote execution of PowerShell commands, potentially allowing an attacker to gain unauthorized access to systems and networks.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- CISA AA24-241A
- Malicious PowerShell

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/pswa_powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_enable_powershell_web_access.yml)*
