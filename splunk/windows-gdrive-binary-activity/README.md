# Windows Gdrive Binary Activity

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

The following analytic detects the execution of the 'gdrive' tool on a Windows host. This tool allows standard users to perform tasks associated with Google Drive via the command line. This is used by actors to stage tools as well as exfiltrate data. The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. If confirmed malicious, this could lead to compromise of systems or sensitive data being stolen.

## MITRE ATT&CK

- T1567

## Analytic Stories

- China-Nexus Threat Activity

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1567/gdrive/gdrive_windows.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_gdrive_binary_activity.yml)*
