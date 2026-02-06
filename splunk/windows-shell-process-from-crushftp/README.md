# Windows Shell Process from CrushFTP

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies instances where CrushFTP's service process (crushftpservice.exe) spawns shell processes like cmd.exe or powershell.exe. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events. This activity is significant because CrushFTP should not normally spawn interactive shell processes during regular operations. If confirmed malicious, this behavior could indicate successful exploitation of vulnerabilities like CVE-2025-31161, potentially allowing attackers to execute arbitrary commands with the privileges of the CrushFTP service.

## MITRE ATT&CK

- T1059.001
- T1059.003
- T1190
- T1505

## Analytic Stories

- CrushFTP Vulnerabilities

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/crushftp/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_shell_process_from_crushftp.yml)*
