# Disable Windows App Hotkeys

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects a suspicious registry modification aimed at disabling Windows hotkeys for native applications. It leverages data from the Endpoint.Registry data model, focusing on specific registry paths and values indicative of this behavior. This activity is significant as it can impair an analyst's ability to use essential tools like Task Manager and Command Prompt, hindering incident response efforts. If confirmed malicious, this technique can allow an attacker to maintain persistence and evade detection, complicating the remediation process.

## MITRE ATT&CK

- T1112
- T1562.001

## Analytic Stories

- XMRig
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/hotkey_disabled_hidden_user/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_windows_app_hotkeys.yml)*
