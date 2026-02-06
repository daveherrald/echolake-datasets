# Windows SQLCMD Execution

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This detection identifies potentially suspicious usage of sqlcmd.exe, focusing on command patterns that may indicate data exfiltration, reconnaissance, or malicious database operations. The detection looks for both short-form (-X) and long-form (--flag) suspicious parameter combinations, which have been observed in APT campaigns targeting high-value organizations. For example, threat actors like CL-STA-0048 have been known to abuse sqlcmd.exe for data theft and exfiltration from compromised MSSQL servers. The detection monitors for suspicious authentication attempts, output redirection, and potentially malicious query patterns that could indicate unauthorized database access or data theft.

## MITRE ATT&CK

- T1059.003

## Analytic Stories

- SQL Server Abuse
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/atomic_red_team/sqlcmd_windows_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sqlcmd_execution.yml)*
