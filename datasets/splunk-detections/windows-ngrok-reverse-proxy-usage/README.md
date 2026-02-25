# Windows Ngrok Reverse Proxy Usage

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of ngrok.exe on a Windows operating system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because while ngrok is a legitimate tool for creating secure tunnels, it is increasingly used by adversaries to bypass network defenses and establish reverse proxies. If confirmed malicious, this could allow attackers to exfiltrate data, maintain persistence, or facilitate further attacks by tunneling traffic through the compromised system.

## MITRE ATT&CK

- T1572
- T1090
- T1102

## Analytic Stories

- Reverse Network Proxy
- CISA AA22-320A
- CISA AA24-241A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1572/ngrok/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ngrok_reverse_proxy_usage.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
