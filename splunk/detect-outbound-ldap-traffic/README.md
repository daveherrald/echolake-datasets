# Detect Outbound LDAP Traffic

**Type:** Hunting

**Author:** Bhavin Patel, Johan Bjerke, Splunk

## Description

The following analytic identifies outbound LDAP traffic to external IP addresses. It leverages the Network_Traffic data model to detect connections on ports 389 or 636 that are not directed to private IP ranges (RFC1918). This activity is significant because outbound LDAP traffic can indicate potential data exfiltration or unauthorized access attempts. If confirmed malicious, attackers could exploit this to access sensitive directory information, leading to data breaches or further network compromise.

## MITRE ATT&CK

- T1190
- T1059

## Analytic Stories

- Log4Shell CVE-2021-44228
- Cisco Secure Firewall Threat Defense Analytics

## Data Sources

- Palo Alto Network Traffic
- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** pan:traffic
  **Sourcetype:** pan:traffic
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/log4shell_ldap_traffic/pantraffic.log

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/detect_outbound_ldap_traffic.yml)*
