# Protocols passing authentication in cleartext

**Type:** Anomaly

**Author:** Rico Valdez, Splunk

## Description

The following analytic identifies the use of cleartext protocols that risk leaking sensitive information. It detects network traffic on legacy protocols such as Telnet (port 23), POP3 (port 110), IMAP (port 143), and non-anonymous FTP (port 21). The detection leverages the Network_Traffic data model to identify TCP traffic on these ports. Monitoring this activity is crucial as it can expose credentials and other sensitive data to interception. If confirmed malicious, attackers could capture authentication details, leading to unauthorized access and potential data breaches.

## Analytic Stories

- Use of Cleartext Protocols
- Cisco Secure Firewall Threat Defense Analytics
- Scattered Lapsus$ Hunters

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/protocols_passing_authentication_in_cleartext.yml)*
