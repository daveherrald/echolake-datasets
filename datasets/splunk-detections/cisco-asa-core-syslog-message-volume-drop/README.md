# Cisco ASA - Core Syslog Message Volume Drop

**Type:** Hunting

**Author:** Bhavin Patel, Micheal Haag, Splunk

## Description

Adversaries may intentionally suppress or reduce the volume of core Cisco ASA syslog messages to evade detection or cover their tracks. This hunting search is recommended to proactively identify suspicious downward shifts or absences in key syslog message IDs, which may indicate tampering or malicious activity. Visualizing this data in Splunk dashboards enables security teams to quickly spot anomalies and investigate potential compromise.


## MITRE ATT&CK

- T1562

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity
- ArcaneDoor

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/arcane_door/cisco_asa.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___core_syslog_message_volume_drop.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
