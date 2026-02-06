# Cisco Secure Firewall - File Download Over Uncommon Port

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects file transfers flagged as malware that occurred over non-standard ports (other than 80 and 443). Adversaries may attempt to bypass protocol-based detection or use alternate ports to blend in with other traffic. This analytic identifies these non-conventional flows and surfaces potential evasion techniques. If confirmed malicious this indicate potential malware delivery or other nefarious activity.


## MITRE ATT&CK

- T1105
- T1571

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense File Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/file_event/file_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___file_download_over_uncommon_port.yml)*
