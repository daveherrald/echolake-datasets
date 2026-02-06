# HTTP Duplicated Header

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

Detects when a request has more than one of the same header. This is commonly used in request smuggling and other web based attacks. HTTP Request Smuggling exploits inconsistencies in how front-end and back-end servers parse HTTP requests by using ambiguous or malformed headers to hide malicious requests within legitimate ones. Attackers leverage duplicate headers, particularly Content-Length and Transfer-Encoding, to cause different servers in the chain to disagree on where one request ends and another begins. RFC7230 states that a sender MUST NOT generate multiple header fields with the same field name in a message unless either the entire field value for that header field is defined as a comma-separated list or the header field is a well-known exception.

## MITRE ATT&CK

- T1071.001
- T1190

## Analytic Stories

- HTTP Request Smuggling

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/request_smuggling/suricata_request_smuggling.log


---

*Source: [Splunk Security Content](detections/web/http_duplicated_header.yml)*
