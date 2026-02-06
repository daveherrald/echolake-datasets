# Cisco Secure Firewall - SSH Connection to sshd_operns

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects inbound SSH connections to the sshd_operns service on network devices using Cisco Secure Firewall Intrusion Events.
APT actors have been observed enabling sshd_operns and opening it on non-standard ports to maintain encrypted remote access to compromised network infrastructure.
This detection leverages Snort signature 65368 to identify connections to this service, which when combined with other indicators may signal persistent access mechanisms established by threat actors.


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

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___ssh_connection_to_sshd_operns.yml)*
