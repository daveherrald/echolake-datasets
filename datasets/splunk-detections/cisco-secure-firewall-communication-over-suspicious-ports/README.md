# Cisco Secure Firewall - Communication Over Suspicious Ports

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting potential reverse shell activity by identifying connections involving ports commonly associated with remote access tools, shell listeners, or tunneling utilities. It leverages Cisco Secure Firewall Threat Defense logs and monitors destination ports against a list of non-standard, high-risk port values often used in post-exploitation scenarios. Adversaries frequently configure tools like netcat, Meterpreter, or other backdoors to listen or connect over uncommon ports such as 4444, 2222, or 51820 to bypass standard monitoring and firewall rules. If confirmed malicious, this activity may represent command and control (C2) tunneling, lateral movement, or unauthorized remote access.


## MITRE ATT&CK

- T1021
- T1055
- T1059.001
- T1105
- T1219
- T1571

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___communication_over_suspicious_ports.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
