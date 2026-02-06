# Windows Rundll32 WebDAV Request

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the execution of rundll32.exe with command-line arguments loading davclnt.dll and the davsetcookie function to access a remote WebDAV instance. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it may indicate an attempt to exploit CVE-2023-23397, a known vulnerability. If confirmed malicious, this could allow an attacker to execute remote code or exfiltrate data, posing a severe threat to the environment.

## MITRE ATT&CK

- T1048.003

## Analytic Stories

- CVE-2023-23397 Outlook Elevation of Privilege

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/cve-2023-23397/webdav_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rundll32_webdav_request.yml)*
