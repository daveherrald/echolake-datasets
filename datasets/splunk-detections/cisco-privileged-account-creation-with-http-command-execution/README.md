# Cisco Privileged Account Creation with HTTP Command Execution

**Type:** Correlation

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic correlates risk events between privileged account creation on Cisco IOS devices and HTTP requests to privileged execution paths such as `/level/15/exec/-/*`.
APT actors have been observed creating privileged accounts and then running commands on routers via HTTP GET or POST requests that target privileged execution paths.
These requests allow attackers to execute commands with the highest privilege level (15) on Cisco devices without requiring interactive SSH access.
This correlation identifies when both "Cisco IOS Suspicious Privileged Account Creation" and "Privileged Command Execution via HTTP" Snort detections fire for the same network device.
This behavior indicates an attacker leveraging the newly created account to execute commands remotely via HTTP.


## MITRE ATT&CK

- T1021.004
- T1136
- T1078

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics
- Salt Typhoon

## Data Sources


## Sample Data

- **Source:** not_applicable
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/emerging_threats/SaltTyphoon/salttyphoon_correlation.log


---

*Source: [Splunk Security Content](detections/network/cisco_privileged_account_creation_with_http_command_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
