# Cisco Secure Firewall - React Server Components RCE Attempt

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk, Talos NTDR

## Description

This analytic detects exploitation activity of CVE-2025-55182 using Cisco Secure Firewall Intrusion Events.
It leverages Cisco Secure Firewall Threat Defense IntrusionEvent logs to identify cases where Snort signature 65554 (React Server Components remote code execution attempt) is triggered
If confirmed malicious, this behavior could be indicative of a potential exploitation of CVE-2025-55182.


## MITRE ATT&CK

- T1190

## Analytic Stories

- React2Shell

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/react2shell/react2shell.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___react_server_components_rce_attempt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
