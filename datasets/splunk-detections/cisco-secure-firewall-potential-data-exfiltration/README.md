# Cisco Secure Firewall - Potential Data Exfiltration

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting potentially suspicious large outbound data transfers from internal to external networks. It leverages Cisco Secure Firewall Threat Defense logs and calculates the total volume of data exchanged per connection by summing InitiatorBytes and ResponderBytes. Connections exceeding 100 MB are flagged, as these may indicate unauthorized data exfiltration, especially if initiated by unusual users, hosts, or processes. This analytic is scoped to inside-to-outside flows using a macro (cisco_secure_firewall_inside_to_outside) to abstract environment-specific zone definitions. If confirmed malicious, this behavior may reflect data staging and exfiltration over an encrypted or stealthy transport.


## MITRE ATT&CK

- T1041
- T1567.002
- T1048.003

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___potential_data_exfiltration.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
