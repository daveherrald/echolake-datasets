# Cisco Secure Firewall - Lumma Stealer Activity

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk, Talos NTDR

## Description

This analytic detects Lumma Stealer activity using Cisco Secure Firewall Intrusion Events. 
It leverages Cisco Secure Firewall Threat Defense IntrusionEvent logs to identify cases where four of the following Snort signature IDs 64793, 64794, 64797, 64798, 64799, 64800, 64801, 62709, 64167, 64168, 64169, 64796, 62710, 62711, 62712, 62713, 62714, 62715, 62716, 62717, 64812, 64810, 64811 occurs in the span of 15 minutes from the same host.
If confirmed malicious, this behavior is highly indicative of a successful infection of Lumma Stealer.


## MITRE ATT&CK

- T1190
- T1210
- T1027
- T1204

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

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___lumma_stealer_activity.yml)*
