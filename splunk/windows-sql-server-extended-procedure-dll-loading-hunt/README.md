# Windows SQL Server Extended Procedure DLL Loading Hunt

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This analytic detects when SQL Server loads DLLs to execute extended stored procedures. This is particularly important for security monitoring as it indicates the first-time use or version changes of potentially dangerous procedures like xp_cmdshell, sp_OACreate, and others. While this is a legitimate operation, adversaries may abuse these procedures for execution, discovery, or privilege escalation.

## MITRE ATT&CK

- T1505.001
- T1059.009

## Analytic Stories

- SQL Server Abuse

## Data Sources

- Windows Event Log Application 8128

## Sample Data

- **Source:** XmlWinEventLog:Application
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.001/simulation/dllprocedureload_windows-application.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sql_server_extended_procedure_dll_loading_hunt.yml)*
