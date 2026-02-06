# Disabling SystemRestore In Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects the modification of registry keys to disable System Restore on a machine. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to registry paths associated with System Restore settings. This activity is significant because disabling System Restore can hinder recovery efforts and is a tactic often used by Remote Access Trojans (RATs) to maintain persistence on an infected system. If confirmed malicious, this action could prevent system recovery, allowing the attacker to sustain their foothold and potentially cause further damage or data loss.

## MITRE ATT&CK

- T1490

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse
- NjRAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** WinEventLog:Security
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-security.log

- **Source:** WinEventLog:System
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-system.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/disabling_systemrestore_in_registry.yml)*
