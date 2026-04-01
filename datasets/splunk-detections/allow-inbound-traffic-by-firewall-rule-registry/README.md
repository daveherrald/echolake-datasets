# Allow Inbound Traffic By Firewall Rule Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting suspicious modifications to firewall rule registry settings that allow inbound traffic on specific ports with a public profile. It leverages data from the Endpoint.Registry data model, focusing on registry paths and values indicative of such changes. This activity is significant as it may indicate an adversary attempting to grant remote access to a machine by modifying firewall rules. If confirmed malicious, this could enable unauthorized remote access, potentially leading to further exploitation, data exfiltration, or lateral movement within the network.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Windows Registry Abuse
- NjRAT
- PlugX
- Prohibited Traffic Allowed or Protocol Mismatch
- Medusa Ransomware
- Azorult

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/allow_inbound_traffic_by_firewall_rule_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
