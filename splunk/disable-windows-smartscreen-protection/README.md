# Disable Windows SmartScreen Protection

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects modifications to the Windows registry that disable SmartScreen protection. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to registry paths associated with SmartScreen settings. This activity is significant because SmartScreen provides an early warning system against phishing and malware. Disabling it can indicate malicious intent, often seen in Remote Access Trojans (RATs) to evade detection while downloading additional payloads. If confirmed malicious, this action could allow attackers to bypass security measures, increasing the risk of successful phishing attacks and malware infections.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- CISA AA23-347A
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_windows_smartscreen_protection.yml)*
