# Disabling CMD Application

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting modifications to the registry that disable the CMD prompt application. It leverages data from the Endpoint.Registry data model, specifically looking for changes to the "DisableCMD" registry value. This activity is significant because disabling CMD can hinder an analyst's ability to investigate and remediate threats, a tactic often used by malware such as RATs, Trojans, or Worms. If confirmed malicious, this could prevent security teams from using CMD for directory and file traversal, complicating incident response and allowing the attacker to maintain persistence.

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

*Source: [Splunk Security Content](detections/endpoint/disabling_cmd_application.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
