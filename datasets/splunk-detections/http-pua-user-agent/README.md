# HTTP PUA User Agent

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

This Splunk query analyzes web logs to identify and categorize user agents, detecting various types of unwanted applications. This activity can signify possible compromised hosts on the network.

## MITRE ATT&CK

- T1071.001

## Analytic Stories

- Local Privilege Escalation With KrbRelayUp
- BlackSuit Ransomware
- Cactus Ransomware
- Suspicious User Agents

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1071.001/http_user_agents/suricata_pua.log


---

*Source: [Splunk Security Content](detections/network/http_pua_user_agent.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
