# Cisco Secure Firewall - Bits Network Activity

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting the use of the Background Intelligent Transfer Service (BITS) client application in allowed outbound connections. It leverages logs from Cisco Secure Firewall Threat Defense devices and identifies instances where BITS is used to initiate downloads from non-standard or unexpected domains. While BITS is a legitimate Windows service used for downloading updates, it is also commonly abused by adversaries to stealthily retrieve payloads or tools. This analytic filters out known Microsoft Edge update URLs and focuses on connections that may indicate suspicious or unauthorized file transfers. If confirmed malicious, this could represent a command and control (C2) channel or a download of malware or tooling as part of an attack chain.

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___bits_network_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
