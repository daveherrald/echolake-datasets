# Prohibited Network Traffic Allowed

**Type:** TTP

**Author:** Rico Valdez, Splunk

## Description

This dataset contains sample data for detecting instances where network traffic, identified by port and transport layer protocol as prohibited in the "lookup_interesting_ports" table, is allowed. It uses the Network_Traffic data model to cross-reference traffic data against predefined security policies. This activity is significant for a SOC as it highlights potential misconfigurations or policy violations that could lead to unauthorized access or data exfiltration. If confirmed malicious, this could allow attackers to bypass network defenses, leading to potential data breaches and compromising the organization's security posture.

## MITRE ATT&CK

- T1048

## Analytic Stories

- Prohibited Traffic Allowed or Protocol Mismatch
- Ransomware
- Command And Control
- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/prohibited_network_traffic_allowed.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
