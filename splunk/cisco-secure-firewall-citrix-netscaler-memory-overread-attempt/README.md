# Cisco Secure Firewall - Citrix NetScaler Memory Overread Attempt

**Type:** TTP

**Author:** Michael Haag, Nasreddine Bencherchali, Splunk, Talos NTDR

## Description

This analytic detects exploitation activity of CVE-2025-5777 using Cisco Secure Firewall Intrusion Events.
It leverages Cisco Secure Firewall Threat Defense IntrusionEvent logs to identify cases where Snort signature 65118 (Citrix NetScaler memory overread attempt) is triggered
If confirmed malicious, this behavior is highly indicative of a potential exploitation of CVE-2025-5777.


## MITRE ATT&CK

- T1203
- T1059

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics
- Citrix NetScaler ADC and NetScaler Gateway CVE-2025-5777

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/intrusion_event/intrusion_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___citrix_netscaler_memory_overread_attempt.yml)*
