# Cisco Secure Firewall - Blacklisted SSL Certificate Fingerprint

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting the use of known suspicious SSL certificates in any observed event where the SSL_CertFingerprint field is present. It leverages Cisco Secure Firewall logs and compares the SSL certificate SHA1 fingerprint against a blacklist of certificates associated with malware distribution, command and control (C2) infrastructure, or phishing campaigns. This activity is significant as adversaries often reuse or self-sign certificates across malicious infrastructure, allowing defenders to track and detect encrypted sessions even when domains or IPs change. If confirmed malicious, this may indicate beaconing, malware download, or data exfiltration over TLS/SSL.


## MITRE ATT&CK

- T1587.002
- T1588.004
- T1071.001
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

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___blacklisted_ssl_certificate_fingerprint.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
