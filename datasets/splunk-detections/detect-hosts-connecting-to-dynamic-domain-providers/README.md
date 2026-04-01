# Detect hosts connecting to dynamic domain providers

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying DNS queries from internal hosts to dynamic domain providers. It leverages DNS query logs from the `Network_Resolution` data model and cross-references them with a lookup file containing known dynamic DNS providers. This activity is significant because attackers often use dynamic DNS services to host malicious payloads or command-and-control servers, making it crucial for security teams to monitor. If confirmed malicious, this activity could allow attackers to bypass firewall blocks, evade detection, and maintain persistent access to the network.

## MITRE ATT&CK

- T1189

## Analytic Stories

- Data Protection
- Prohibited Traffic Allowed or Protocol Mismatch
- DNS Hijacking
- Suspicious DNS Traffic
- Dynamic DNS
- Command And Control

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1189/dyn_dns_site/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/network/detect_hosts_connecting_to_dynamic_domain_providers.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
