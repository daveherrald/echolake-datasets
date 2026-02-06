# Windows Impair Defense Override SmartScreen Prompt

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry that override the Windows Defender SmartScreen prompt. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the "PreventSmartScreenPromptOverride" registry setting. This activity is significant because it indicates an attempt to disable the prevention of user overrides for SmartScreen prompts, potentially allowing users to bypass security warnings. If confirmed malicious, this could lead to users inadvertently executing or accessing harmful content, increasing the risk of security incidents or system compromises.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable-windows-security-defender-features/windefender-bypas-2-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_override_smartscreen_prompt.yml)*
