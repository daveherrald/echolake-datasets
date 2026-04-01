# Cisco NVM - Outbound Connection to Suspicious Port

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting any outbound network connection from an endpoint process to a known suspicious or non-standard port.
It leverages Cisco Network Visibility Module flow data logs to identify potentially suspicious behavior by looking at processes
communicating over ports like 4444, 2222, or 51820 are commonly used by tools like Metasploit, SliverC2 or other pentest, red team or malware.
These connections are worth investigating further, especially when initiated by unexpected or non-network-native binaries.


## MITRE ATT&CK

- T1571

## Analytic Stories

- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___outbound_connection_to_suspicious_port.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
