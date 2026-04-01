# Cisco Secure Firewall - Snort Rule Triggered Across Multiple Hosts

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic identifies Snort intrusion signatures that have been triggered by ten or more distinct internal IP addresses within a one-hour window. It leverages Cisco Secure Firewall Threat Defense logs and focuses on the IntrusionEvent event type to detect activity that may indicate broad targeting or mass exploitation attempts. This behavior is often associated with opportunistic scanning, worm propagation, or automated exploitation of known vulnerabilities across multiple systems. If confirmed malicious, this could represent the early phase of a coordinated attack aiming to gain a foothold on several hosts or move laterally across the environment.


## MITRE ATT&CK

- T1105
- T1027

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/intrusion_event/intrusion_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___snort_rule_triggered_across_multiple_hosts.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
