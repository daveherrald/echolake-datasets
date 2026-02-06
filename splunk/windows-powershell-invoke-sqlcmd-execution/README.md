# Windows PowerShell Invoke-Sqlcmd Execution

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This detection identifies potentially suspicious usage of Invoke-Sqlcmd PowerShell cmdlet, which can be used for database operations and potential data exfiltration. The detection looks for suspicious parameter combinations and query patterns that may indicate unauthorized database access, data theft, or malicious database operations. Threat actors may prefer using PowerShell Invoke-Sqlcmd over sqlcmd.exe as it provides a more flexible programmatic interface and can better evade detection.

## MITRE ATT&CK

- T1059.001
- T1059.003

## Analytic Stories

- SQL Server Abuse
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/atomic_red_team/invokesqlcmd_powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_invoke_sqlcmd_execution.yml)*
