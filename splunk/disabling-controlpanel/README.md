# Disabling ControlPanel

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects registry modifications that disable the Control Panel on Windows systems. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoControlPanel" with a value of "0x00000001". This activity is significant as it is commonly used by malware to prevent users from accessing the Control Panel, thereby hindering the removal of malicious artifacts and persistence mechanisms. If confirmed malicious, this could allow attackers to maintain control over the infected machine and prevent remediation efforts.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/disabling_controlpanel.yml)*
