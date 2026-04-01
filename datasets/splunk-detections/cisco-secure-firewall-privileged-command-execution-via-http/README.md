# Cisco Secure Firewall - Privileged Command Execution via HTTP

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Michael Haag, Splunk

## Description

This analytic detects HTTP requests to privileged execution paths on Cisco routers, specifically targeting the `/level/15/exec/-/*` endpoint using Cisco Secure Firewall Intrusion Events.
This detection leverages Snort signature 65370 to identify requests to these sensitive endpoints, which when combined with other indicators may signal active exploitation or post-compromise activity.


## MITRE ATT&CK

- T1059
- T1505.003

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics
- Salt Typhoon

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/intrusion_event/intrusion_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___privileged_command_execution_via_http.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
