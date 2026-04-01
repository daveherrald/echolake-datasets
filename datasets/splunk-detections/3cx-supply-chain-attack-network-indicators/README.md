# 3CX Supply Chain Attack Network Indicators

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying DNS queries to domains associated with the 3CX supply chain attack. It leverages the Network_Resolution datamodel to detect these suspicious domain indicators. This activity is significant because it can indicate a potential compromise stemming from the 3CX supply chain attack, which is known for distributing malicious software through trusted updates. If confirmed malicious, this activity could allow attackers to establish a foothold in the network, exfiltrate sensitive data, or further propagate malware, leading to extensive damage and data breaches.

## MITRE ATT&CK

- T1195.002

## Analytic Stories

- 3CX Supply Chain Attack

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.002/3CX/3cx_network-windows-sysmon.log


---

*Source: [Splunk Security Content](detections/network/3cx_supply_chain_attack_network_indicators.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
