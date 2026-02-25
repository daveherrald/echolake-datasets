# Ngrok Reverse Proxy on Network

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting DNS queries to common Ngrok domains, indicating potential use of the Ngrok reverse proxy tool. It leverages the Network Resolution datamodel to identify queries to domains such as "*.ngrok.com" and "*.ngrok.io". While Ngrok usage is not inherently malicious, it has been increasingly adopted by adversaries for covert communication and data exfiltration. If confirmed malicious, this activity could allow attackers to bypass network defenses, establish persistent connections, and exfiltrate sensitive data, posing a significant threat to the network's security.

## MITRE ATT&CK

- T1572
- T1090
- T1102

## Analytic Stories

- Reverse Network Proxy
- CISA AA22-320A
- CISA AA24-241A

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1572/ngrok/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/network/ngrok_reverse_proxy_on_network.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
