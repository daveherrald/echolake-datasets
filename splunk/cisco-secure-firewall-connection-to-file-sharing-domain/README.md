# Cisco Secure Firewall - Connection to File Sharing Domain

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects outbound connections to commonly abused file sharing and pastebin-style hosting domains. It leverages Cisco Secure Firewall Threat Defense logs and focuses on allowed connections (action=Allow) where the url field matches a list of known data hosting or temporary storage services. While many of these platforms serve legitimate purposes, they are frequently leveraged by adversaries for malware delivery, data exfiltration, command and control (C2) beacons, or staging of encoded payloads. This analytic is valuable for identifying potential abuse of legitimate infrastructure as part of an attacker's kill chain. If confirmed malicious, this activity may indicate tool staging, credential dumping, or outbound data leaks over HTTP(S).


## MITRE ATT&CK

- T1071.001
- T1090.002
- T1105
- T1567.002
- T1588.002

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics
- Scattered Lapsus$ Hunters

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___connection_to_file_sharing_domain.yml)*
