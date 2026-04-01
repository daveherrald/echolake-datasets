# Windows Firewall Rule Modification

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies instances where a Windows Firewall rule has been modified, which may indicate an attempt to alter security policies. Unauthorized modifications can weaken firewall protections, allowing malicious traffic or preventing legitimate communications. The event logs details such as the modified rule name, protocol, ports, application path, and the user responsible for the change. Security teams should monitor unexpected modifications, correlate them with related events, and investigate anomalies to prevent unauthorized access and maintain network security integrity.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- ShrinkLocker
- Medusa Ransomware
- NetSupport RMM Tool Abuse

## Data Sources

- Windows Event Log Security 4947

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/firewall_win_event/modify_rule/MPSSVC_Rule-Level_Policy_Change-4947.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_firewall_rule_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
