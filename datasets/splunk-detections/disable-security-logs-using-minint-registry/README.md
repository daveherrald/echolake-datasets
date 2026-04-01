# Disable Security Logs Using MiniNt Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting a suspicious registry modification aimed at disabling security audit logs by adding a specific registry entry. It leverages data from the Endpoint.Registry data model, focusing on changes to the "Control\\MiniNt" registry path. This activity is significant because it can prevent Windows from logging any events to the Security Log, effectively blinding security monitoring efforts. If confirmed malicious, this technique could allow an attacker to operate undetected, making it difficult to trace their actions and compromising the integrity of security audits.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Windows Defense Evasion Tactics
- CISA AA23-347A
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/minint_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_security_logs_using_minint_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
