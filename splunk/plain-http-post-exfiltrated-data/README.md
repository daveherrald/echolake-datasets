# Plain HTTP POST Exfiltrated Data

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects potential data exfiltration using plain HTTP POST requests. It leverages network traffic logs, specifically monitoring the `stream_http` data source for POST methods containing suspicious form data such as "wermgr.exe" or "svchost.exe". This activity is significant because it is commonly associated with malware like Trickbot, trojans, keyloggers, or APT adversaries, which use plain text HTTP POST requests to communicate with remote C2 servers. If confirmed malicious, this activity could lead to unauthorized data exfiltration, compromising sensitive information and potentially leading to further network infiltration.

## MITRE ATT&CK

- T1048.003

## Analytic Stories

- Data Exfiltration
- Command And Control
- APT37 Rustonotto and FadeStealer

## Data Sources

- Splunk Stream HTTP

## Sample Data

- **Source:** stream
  **Sourcetype:** stream:http
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/plain_exfil_data/stream_http_events.log


---

*Source: [Splunk Security Content](detections/web/plain_http_post_exfiltrated_data.yml)*
