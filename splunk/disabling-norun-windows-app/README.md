# Disabling NoRun Windows App

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects the modification of the Windows registry to disable the Run application in the Start menu. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRun" with a value of "0x00000001". This activity is significant because the Run application is a useful shortcut for executing known applications and scripts. If confirmed malicious, this action could hinder system cleaning efforts and make it more difficult to run essential tools, thereby aiding malware persistence.

## MITRE ATT&CK

- T1112
- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disabling_norun_windows_app.yml)*
