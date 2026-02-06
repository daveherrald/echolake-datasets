# Cisco Secure Firewall - Blocked Connection

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects a blocked connection event by identifying a "Block" value in the action field. It leverages logs from Cisco Secure Firewall Threat Defense devices. This activity is significant as it can identify attempts from users or applications initiating network connection to explicitly or implicitly blocked range or zones. If confirmed malicious, attackers could be attempting to perform a forbidden action on the network such as data exfiltration, lateral movement, or network disruption.

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

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___blocked_connection.yml)*
