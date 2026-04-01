# Cisco Secure Firewall - High Volume of Intrusion Events Per Host

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting internal systems that generate an unusually high volume of intrusion detections within a 30-minute window. It leverages Cisco Secure Firewall Threat Defense logs, specifically focusing on the IntrusionEvent event type, to identify hosts that trigger more than 15 Snort-based signatures during that time. A sudden spike in intrusion alerts originating from a single host may indicate suspicious or malicious activity such as malware execution, command-and-control communication, vulnerability scanning, or lateral movement. In some cases, this behavior may also be caused by misconfigured or outdated software repeatedly tripping detection rules. Systems exhibiting this pattern should be triaged promptly, as repeated Snort rule matches from a single source are often early indicators of compromise, persistence, or active exploitation attempts.


## MITRE ATT&CK

- T1059
- T1071
- T1595.002

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/intrusion_event/intrusion_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___high_volume_of_intrusion_events_per_host.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
