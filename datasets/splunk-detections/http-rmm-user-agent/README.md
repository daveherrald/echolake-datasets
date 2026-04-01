# HTTP RMM User Agent

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

This Splunk query analyzes web logs to identify and categorize user agents, detecting various types of Remote Monitoring and Mangement applications. This activity can signify possible compromised hosts on the network.

## MITRE ATT&CK

- T1071.001
- T1219

## Analytic Stories

- Remote Monitoring and Management Software
- Suspicious User Agents

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1071.001/http_user_agents/suricata_rmm.log


---

*Source: [Splunk Security Content](detections/network/http_rmm_user_agent.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
