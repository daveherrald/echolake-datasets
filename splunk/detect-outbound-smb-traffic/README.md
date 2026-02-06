# Detect Outbound SMB Traffic

**Type:** TTP

**Author:** Bhavin Patel, Stuart Hopkins, Patrick Bareiss

## Description

The following analytic detects outbound SMB (Server Message Block) connections from internal hosts to external servers. It identifies this activity by monitoring network traffic for SMB requests directed towards the Internet, which are unusual for standard operations. This detection is significant for a SOC as it can indicate an attacker's attempt to retrieve credential hashes through compromised servers, a key step in lateral movement and privilege escalation. If confirmed malicious, this activity could lead to unauthorized access to sensitive data and potential full system compromise.

## MITRE ATT&CK

- T1071.002

## Analytic Stories

- Hidden Cobra Malware
- DHS Report TA18-074A
- NOBELIUM Group
- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/detect_outbound_smb_traffic.yml)*
