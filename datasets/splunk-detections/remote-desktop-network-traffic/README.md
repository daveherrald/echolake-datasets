# Remote Desktop Network Traffic

**Type:** Anomaly

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for detecting unusual Remote Desktop Protocol (RDP) traffic on TCP/3389 by filtering out known RDP sources and destinations, focusing on atypical connections within the network. This detection leverages network traffic data to identify potentially unauthorized RDP access. Monitoring this activity is crucial for a SOC as unauthorized RDP access can indicate an attacker's attempt to control networked systems, leading to data theft, ransomware deployment, or further network compromise. If confirmed malicious, this activity could result in significant data breaches or complete system and network control loss.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- SamSam Ransomware
- Ryuk Ransomware
- Hidden Cobra Malware
- Active Directory Lateral Movement
- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Zeek Conn

## Sample Data

- **Source:** conn.log
  **Sourcetype:** bro:conn:json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.001/remote_desktop_connection/zeek_conn.log


---

*Source: [Splunk Security Content](detections/network/remote_desktop_network_traffic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
