# Linux Ngrok Reverse Proxy Usage

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of Ngrok on a Linux operating system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments associated with Ngrok. This activity is significant because Ngrok can be used by adversaries to establish reverse proxies, potentially bypassing network defenses. If confirmed malicious, this could allow attackers to create persistent, unauthorized access channels, facilitating data exfiltration or further exploitation of the compromised system.

## MITRE ATT&CK

- T1572
- T1090
- T1102

## Analytic Stories

- Reverse Network Proxy

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1572/ngrok/ngrok_linux-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_ngrok_reverse_proxy_usage.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
