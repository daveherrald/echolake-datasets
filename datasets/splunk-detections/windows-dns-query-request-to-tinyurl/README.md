# Windows DNS Query Request To TinyUrl

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a process located in a potentially suspicious location making DNS queries to known URL shortening services, specifically tinyurl.
URL shorteners are frequently used by threat actors to obfuscate malicious destinations, including phishing pages, malware distribution sites, or command-and-control (C2) endpoints. 
While tinyurl.com is a legitimate service, its use in enterprise environments—particularly by non-browser processes or scripts—should be considered suspicious, especially if correlated with subsequent outbound connections, file downloads, process file path or credential prompts. Analysts should investigate the source process, execution context, and destination domain to determine intent and risk.


## MITRE ATT&CK

- T1105

## Analytic Stories

- Malicious Inno Setup Loader

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/tinyurl_dns_query/tinyurl.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dns_query_request_to_tinyurl.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
