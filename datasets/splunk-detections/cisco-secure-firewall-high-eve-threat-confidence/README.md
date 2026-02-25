# Cisco Secure Firewall - High EVE Threat Confidence

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting connections with a high Encrypted Visibility Engine (EVE) threat confidence score, indicating potentially malicious behavior within encrypted traffic. It leverages Cisco Secure Firewall Threat Defense logs and evaluates the EVE_ThreatConfidencePct field, which reflects the system's confidence in classifying encrypted sessions as threats based on machine learning models and behavioral analysis. A score equal to or greater than 80 suggests the connection is highly likely to be associated with malware command and control (C2), remote access tools, or suspicious tunneling behavior. If confirmed malicious, this may indicate covert communication over TLS from compromised hosts.


## MITRE ATT&CK

- T1041
- T1071.001
- T1105
- T1573.002

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___high_eve_threat_confidence.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
