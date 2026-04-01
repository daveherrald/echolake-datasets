# Cisco Secure Firewall - High Priority Intrusion Classification

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic identifies high-severity intrusion events based on the classification assigned to Snort rules within Cisco Secure Firewall logs.
It leverages Cisco Secure Firewall Threat Defense logs and focuses on events classified as:

- A Network Trojan was Detected
- Successful Administrator Privilege Gain
- Successful User Privilege Gain
- Attempt to Login By a Default Username and Password
- Known malware command and control traffic
- Known malicious file or file based exploit
- Known client side exploit attempt
- Large Scale Information Leak"

These classifications typically represent significant threats such as remote code execution, credential theft, lateral movement, or malware communication. Detection of these classifications should be prioritized for immediate investigation.


## MITRE ATT&CK

- T1203
- T1003
- T1071
- T1190
- T1078

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/intrusion_event/intrusion_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___high_priority_intrusion_classification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
