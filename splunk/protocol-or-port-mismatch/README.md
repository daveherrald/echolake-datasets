# Protocol or Port Mismatch

**Type:** Anomaly

**Author:** Rico Valdez, Splunk

## Description

The following analytic identifies network traffic where the higher layer protocol does not match the expected port, such as non-HTTP traffic on TCP port 80. It leverages data from network traffic inspection technologies like Bro or Palo Alto Networks firewalls. This activity is significant because it may indicate attempts to bypass firewall restrictions or conceal malicious communications. If confirmed malicious, this behavior could allow attackers to evade detection, maintain persistence, or exfiltrate data through commonly allowed ports, posing a significant threat to network security.

## MITRE ATT&CK

- T1048.003

## Analytic Stories

- Prohibited Traffic Allowed or Protocol Mismatch
- Command And Control
- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/protocol_or_port_mismatch.yml)*
