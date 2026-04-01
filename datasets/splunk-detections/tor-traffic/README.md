# TOR Traffic

**Type:** TTP

**Author:** David Dorsey, Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying allowed network traffic to The Onion Router (TOR), an anonymity network often exploited for malicious activities. It leverages data from Next Generation Firewalls, using the Network_Traffic data model to detect traffic where the application is TOR and the action is allowed. This activity is significant as TOR can be used to bypass conventional monitoring, facilitating hacking, data breaches, and illicit content dissemination. If confirmed malicious, this could lead to unauthorized access, data exfiltration, and severe compliance violations, compromising the integrity and security of the network.

## MITRE ATT&CK

- T1090.003

## Analytic Stories

- Prohibited Traffic Allowed or Protocol Mismatch
- Ransomware
- NOBELIUM Group
- Command And Control
- Cisco Secure Firewall Threat Defense Analytics
- Interlock Ransomware

## Data Sources

- Palo Alto Network Traffic
- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** pan_tor_allowed
  **Sourcetype:** pan:traffic
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1090.003/pan_tor_allowed/pan_tor_allowed.log

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/tor_traffic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
