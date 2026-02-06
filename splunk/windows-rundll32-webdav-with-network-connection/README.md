# Windows Rundll32 WebDav With Network Connection

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of rundll32.exe with command-line arguments loading davclnt.dll and the davsetcookie function to access a remote WebDav instance. It uses data from Endpoint Detection and Response (EDR) agents, correlating process execution and network traffic data. This activity is significant as it may indicate exploitation of CVE-2023-23397, a known vulnerability. If confirmed malicious, this could allow an attacker to establish unauthorized remote connections, potentially leading to data exfiltration or further network compromise.

## MITRE ATT&CK

- T1048.003

## Analytic Stories

- CVE-2023-23397 Outlook Elevation of Privilege

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/cve-2023-23397/webdav_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rundll32_webdav_with_network_connection.yml)*
