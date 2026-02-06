# Windows SQL Server xp_cmdshell Config Change

**Type:** TTP

**Author:** Michael Haag, Splunk, sidoyle from Splunk Community

## Description

This detection identifies when the xp_cmdshell configuration is modified in SQL Server. The xp_cmdshell extended stored procedure allows execution of operating system commands and programs from SQL Server, making it a high-risk feature commonly abused by attackers for privilege escalation and lateral movement.

## MITRE ATT&CK

- T1505.001

## Analytic Stories

- SQL Server Abuse
- Seashell Blizzard
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Windows Event Log Application 15457

## Sample Data

- **Source:** XmlWinEventLog:Application
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.001/simulation/windows-application.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sql_server_xp_cmdshell_config_change.yml)*
