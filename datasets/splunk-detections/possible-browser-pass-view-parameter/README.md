# Possible Browser Pass View Parameter

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying processes with command-line parameters associated with web browser credential dumping tools, specifically targeting behaviors used by Remcos RAT malware. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and specific file paths. This activity is significant as it indicates potential credential theft, a common tactic in broader cyber-espionage campaigns. If confirmed malicious, attackers could gain unauthorized access to sensitive web credentials, leading to further system compromise and data breaches.

## MITRE ATT&CK

- T1555.003

## Analytic Stories

- Remcos

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/web_browser_pass_view/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/possible_browser_pass_view_parameter.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
