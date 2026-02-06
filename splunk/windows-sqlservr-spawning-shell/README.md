# Windows Sqlservr Spawning Shell

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This analytic detects instances where the sqlservr.exe process spawns a command shell (cmd.exe) or PowerShell process. This behavior is often indicative of command execution initiated from within the SQL Server process, potentially due to exploitation of SQL injection vulnerabilities or the use of extended stored procedures like xp_cmdshell.

## MITRE ATT&CK

- T1505.001

## Analytic Stories

- SQL Server Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.001/simulation/sqlservr-windows_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sqlservr_spawning_shell.yml)*
