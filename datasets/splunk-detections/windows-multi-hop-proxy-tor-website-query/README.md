# Windows Multi hop Proxy TOR Website Query

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying DNS queries to known TOR proxy websites, such as "*.torproject.org" and "www.theonionrouter.com". It leverages Sysmon EventCode 22 to detect these queries by monitoring DNS query events from endpoints. This activity is significant because adversaries often use TOR proxies to disguise the source of their malicious traffic, making it harder to trace their actions. If confirmed malicious, this behavior could indicate an attempt to obfuscate network traffic, potentially allowing attackers to exfiltrate data or communicate with command and control servers undetected.

## MITRE ATT&CK

- T1071.003

## Analytic Stories

- AgentTesla
- Interlock Ransomware

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/agent_tesla/agent_tesla_tor_dns_query/sysmon.log


---

*Source: [Splunk Security Content](detections/network/windows_multi_hop_proxy_tor_website_query.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
