# Cisco Secure Firewall - Static Tundra Smart Install Abuse

**Type:** TTP

**Author:** Bhavin Patel, Michael Haag, Splunk

## Description

This analytic detects activity associated with "Static Tundra" threat actor abuse of the Cisco Smart Install (SMI) protocol
using Cisco Secure Firewall Intrusion Events. It leverages Cisco Secure Firewall Threat Defense IntrusionEvent logs to
identify occurrences of Smart Install exploitation and protocol abuse, including denial-of-service and buffer overflow
attempts. The detection triggers when multiple Cisco Smart Install-related Snort signatures are observed in a short period from the
same source, which is indicative of active exploitation or reconnaissance against Cisco devices that expose SMI. 


## MITRE ATT&CK

- T1190
- T1210
- T1499

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics
- Cisco Smart Install Remote Code Execution CVE-2018-0171

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/static_tundra/static_tundra.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___static_tundra_smart_install_abuse.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
