# Disable Registry Tool

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects modifications to the Windows registry aimed at disabling the Registry Editor (regedit). It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" with a value of "0x00000001". This activity is significant because malware, such as RATs or trojans, often disable registry tools to prevent the removal of their entries, aiding in persistence and defense evasion. If confirmed malicious, this could hinder incident response efforts and allow the attacker to maintain control over the compromised system.

## MITRE ATT&CK

- T1112
- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse
- NjRAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_registry_tool.yml)*
