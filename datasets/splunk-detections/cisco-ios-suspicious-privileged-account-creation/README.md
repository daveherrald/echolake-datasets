# Cisco IOS Suspicious Privileged Account Creation

**Type:** Anomaly

**Author:** Bhavin Patel, Michael Haag, Splunk

## Description

This analytic detects the creation of privileged user accounts on Cisco IOS devices, which could indicate an attacker establishing backdoor access. The detection focuses on identifying when user accounts are created with privilege level 15 (the highest administrative privilege level in Cisco IOS) or when existing accounts have their privileges elevated. This type of activity is particularly concerning when performed by unauthorized users or during unusual hours, as it may represent a key step in establishing persistence following the exploitation of vulnerabilities like CVE-2018-0171 in Cisco Smart Install. Threat actors like Static Tundra have been observed creating privileged accounts as part of their attack chain after gaining initial access to network devices.

## MITRE ATT&CK

- T1136
- T1078

## Analytic Stories

- Cisco Smart Install Remote Code Execution CVE-2018-0171

## Data Sources

- Cisco IOS Logs

## Sample Data

- **Source:** cisco:ios
  **Sourcetype:** cisco:ios
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/cisco/cisco_smart_install/cisco_ios.log


---

*Source: [Splunk Security Content](detections/network/cisco_ios_suspicious_privileged_account_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
