# Windows SharePoint Spinstall0 Webshell File Creation

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This detection identifies the creation or modification of the "spinstall0.aspx" webshell file in Microsoft SharePoint directories. This file is a known indicator of compromise associated with the exploitation of CVE-2025-53770 (ToolShell vulnerability). Attackers exploit the vulnerability to drop webshells that provide persistent access to compromised SharePoint servers, allowing them to execute arbitrary commands, access sensitive data, and move laterally within the network.

## MITRE ATT&CK

- T1190
- T1505.003

## Analytic Stories

- Microsoft SharePoint Vulnerabilities

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/sharepoint_webshell/sysmon_spinstall0.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sharepoint_spinstall0_webshell_file_creation.yml)*
