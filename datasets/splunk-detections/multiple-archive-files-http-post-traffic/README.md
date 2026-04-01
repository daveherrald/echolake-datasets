# Multiple Archive Files Http Post Traffic

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the high-frequency exfiltration of archive files via HTTP POST requests. It leverages HTTP stream logs to identify specific archive file headers within the request body. This activity is significant as it often indicates data exfiltration by APTs or trojan spyware after data collection. If confirmed malicious, this behavior could lead to the unauthorized transfer of sensitive data to an attacker’s command and control server, potentially resulting in severe data breaches and loss of confidential information.

## MITRE ATT&CK

- T1048.003

## Analytic Stories

- Data Exfiltration
- Command And Control
- APT37 Rustonotto and FadeStealer
- Hellcat Ransomware

## Data Sources

- Splunk Stream HTTP

## Sample Data

- **Source:** stream
  **Sourcetype:** stream:http
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/archive_http_post/stream_http_events.log


---

*Source: [Splunk Security Content](detections/web/multiple_archive_files_http_post_traffic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
