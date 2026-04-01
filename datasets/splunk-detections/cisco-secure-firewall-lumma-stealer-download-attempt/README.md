# Cisco Secure Firewall - Lumma Stealer Download Attempt

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk, Talos NTDR

## Description

This analytic detects Lumma Stealer download attempts using Cisco Secure Firewall Intrusion Events. 
It leverages Cisco Secure Firewall Threat Defense IntrusionEvent logs to identify cases where Snort signatures with IDs 64797, 64798, 64799, 64800, 64801, 64167, 64168, 64169 have been triggered. If confirmed malicious, this behavior could indicate an active infection of Lumma Stealer.


## MITRE ATT&CK

- T1041
- T1573.002

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics
- Lumma Stealer

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/lumma_stealer/lumma_stealer_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___lumma_stealer_download_attempt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
