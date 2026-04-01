# LOLBAS With Network Traffic

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying the use of Living Off the Land Binaries and Scripts (LOLBAS) with network traffic. It leverages data from the Network Traffic data model to detect when native Windows binaries, often abused by adversaries, initiate network connections. This activity is significant as LOLBAS are frequently used to download malicious payloads, enabling lateral movement, command-and-control, or data exfiltration. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment, posing a severe threat to organizational security.

## MITRE ATT&CK

- T1105
- T1567
- T1218

## Analytic Stories

- Fake CAPTCHA Campaigns
- Living Off The Land
- Malicious Inno Setup Loader
- Water Gamayun
- APT37 Rustonotto and FadeStealer
- GhostRedirector IIS Module and Rungan Backdoor
- Hellcat Ransomware
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218/lolbas_with_network_traffic/lolbas_with_network_traffic.log


---

*Source: [Splunk Security Content](detections/endpoint/lolbas_with_network_traffic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
