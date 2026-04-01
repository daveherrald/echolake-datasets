# Cisco Secure Firewall - SSH Connection to Non-Standard Port

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Michael Haag, Splunk

## Description

This analytic detects inbound SSH connections to non-standard ports on network devices using Cisco Secure Firewall Intrusion Events. APT actors have been observed enabling SSH servers on high, non-default TCP ports to maintain encrypted remote access to compromised network infrastructure.
This detection leverages Snort signature 65369 to identify SSH protocol traffic on unusual ports, which may indicate persistence mechanisms or backdoor access established by threat actors.


## MITRE ATT&CK

- T1021.004

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics
- Salt Typhoon

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/intrusion_event/intrusion_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___ssh_connection_to_non_standard_port.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
