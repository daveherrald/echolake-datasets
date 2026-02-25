# Cisco Secure Firewall - Rare Snort Rule Triggered

**Type:** Hunting

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic identifies Snort signatures that have triggered only once in the past 7 days across all Cisco Secure Firewall IntrusionEvent logs. While these rules typically do not trigger in day-to-day network activity, their sudden appearance may indicate early-stage compromise, previously unseen malware, or reconnaissance activity against less commonly exposed services. Investigating these outliers can provide valuable insight into new or low-noise adversary behaviors.


## MITRE ATT&CK

- T1598
- T1583.006

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/intrusion_event/intrusion_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___rare_snort_rule_triggered.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
