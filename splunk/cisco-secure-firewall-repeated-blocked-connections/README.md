# Cisco Secure Firewall - Repeated Blocked Connections

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects repeated blocked connection attempts from the same initiator to the same responder within a short time window. It leverages Cisco Secure Firewall Threat Defense logs and identifies connections where the action is set to Block, and the number of occurrences reaches or exceeds a threshold of ten within a one-minute span. This pattern may indicate a misconfigured application, unauthorized access attempts, or early stages of a brute-force or scanning operation. If confirmed malicious, this behavior may represent an attacker probing the network, attempting lateral movement, or testing firewall rules for weaknesses.


## MITRE ATT&CK

- T1018
- T1046
- T1110
- T1203
- T1595.002

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___repeated_blocked_connections.yml)*
